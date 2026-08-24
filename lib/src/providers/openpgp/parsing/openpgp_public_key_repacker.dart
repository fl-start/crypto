import 'dart:convert';
import 'dart:typed_data';

import '../../../core/exceptions/crypto_exceptions.dart';

const int _tagPublicKey = 6;
const int _tagPublicSubkey = 14;

/// Extracts the primary public-key packet from an armored or binary OpenPGP
/// public-key block, and re-wraps it as a standalone tag-6 "Public-Key"
/// packet — the only shape some minimal OpenPGP consumers (e.g. a server
/// that only extracts *a* public key, not a whole certificate) know how to
/// read.
///
/// The packet *body* bytes are copied verbatim from the source, byte for
/// byte — this deliberately avoids re-deriving or re-encoding the point
/// encoding. Only the outer packet tag changes; nothing about the key
/// material itself is touched or reinterpreted.
class OpenPgpPublicKeyRepacker {
  const OpenPgpPublicKeyRepacker._();

  /// Returns the full certificate as raw binary — armor removed, but every
  /// packet (primary key, User ID, self-signature, subkeys, subkey-binding
  /// signatures) left byte-for-byte intact.
  ///
  /// Unlike [repackPrimary]/[repackEncryptionSubkey], this does not throw
  /// away any signatures. Use this when the consumer needs a real,
  /// validly-signed OpenPGP certificate (e.g. anything that will later be
  /// parsed by a standards-compliant OpenPGP library for encryption) rather
  /// than a minimal server-side proof-of-possession probe.
  static Uint8List toCertificateBinary(Uint8List publicKeyBytes) =>
      _unwrapArmorIfPresent(publicKeyBytes);

  /// Returns the primary public-key packet (tag 6), re-tagged as itself
  /// (a no-op repack, included for symmetry/clarity at call sites — and so
  /// UID/signature packets bundled in the same block are dropped, which
  /// the server has no use for).
  static Uint8List repackPrimary(Uint8List publicKeyBytes) {
    final packetBytes = _unwrapArmorIfPresent(publicKeyBytes);
    Uint8List? body;
    _forEachPacket(packetBytes, (tag, packetBody) {
      if (body == null && tag == _tagPublicKey) body = packetBody;
    });
    if (body == null) {
      throw const KeyImportException('No primary public-key packet (tag 6) found.');
    }
    return _newFormatPacket(_tagPublicKey, body!);
  }

  /// Returns the first public-subkey packet (tag 14) — e.g. the ECDH
  /// encryption subkey a modern EdDSA/Curve25519 key carries alongside its
  /// Ed25519 primary key — re-tagged as a standalone tag-6 "Public-Key"
  /// packet. OpenPGP primary-key and subkey packet bodies share the same
  /// wire format (RFC 4880 §5.5.2); only the outer tag differs, and a
  /// minimal consumer that only reads standalone tag-6 packets (see
  /// [repackPrimary]) has no notion of subkeys, so this repacks the subkey
  /// body under the tag it expects.
  static Uint8List repackEncryptionSubkey(Uint8List publicKeyBytes) {
    final packetBytes = _unwrapArmorIfPresent(publicKeyBytes);
    Uint8List? body;
    _forEachPacket(packetBytes, (tag, packetBody) {
      if (body == null && tag == _tagPublicSubkey) body = packetBody;
    });
    if (body == null) {
      throw const KeyImportException('No public-subkey packet (tag 14) found.');
    }
    return _newFormatPacket(_tagPublicKey, body!);
  }

  static Uint8List _newFormatPacket(int tag, Uint8List body) {
    final header = <int>[0xC0 | tag];
    if (body.length < 192) {
      header.add(body.length);
    } else if (body.length < 8384) {
      final len = body.length - 192;
      header.addAll([192 + (len >> 8), len & 0xFF]);
    } else {
      header.addAll([
        255,
        (body.length >> 24) & 0xFF,
        (body.length >> 16) & 0xFF,
        (body.length >> 8) & 0xFF,
        body.length & 0xFF,
      ]);
    }
    return Uint8List.fromList([...header, ...body]);
  }

  // ── Armor + packet framing (mirrors OpenPgpSecretKeyParser) ───────────

  static Uint8List _unwrapArmorIfPresent(Uint8List data) {
    if (data.length < 27) return data;
    final prefix = utf8.decode(data.sublist(0, 27), allowMalformed: true);
    if (!prefix.startsWith('-----BEGIN PGP')) return data;
    final text = utf8.decode(data, allowMalformed: true);
    final beginRe = RegExp(r'-----BEGIN PGP ([A-Z ]+?)-----\s*\r?\n', multiLine: true);
    final beginMatch = beginRe.firstMatch(text);
    if (beginMatch == null) {
      throw const CryptoArgumentException('Invalid OpenPGP armor: missing BEGIN header.');
    }
    final type = beginMatch.group(1)!.trim();
    final bodyStart = beginMatch.end;
    final endMarker = '-----END PGP $type-----';
    final endIndex = text.indexOf(endMarker, bodyStart);
    if (endIndex < 0) {
      throw CryptoArgumentException('Invalid OpenPGP armor: missing END header for "$type".');
    }
    final bodySection = text.substring(bodyStart, endIndex);
    final b64 = bodySection
        .split(RegExp(r'\r?\n'))
        .map((l) => l.trim())
        .where((l) => l.isNotEmpty && !l.startsWith('=') && RegExp(r'^[A-Za-z0-9+/]+=*$').hasMatch(l))
        .join();
    return base64Decode(b64);
  }

  static void _forEachPacket(
    Uint8List data,
    void Function(int tag, Uint8List body) onPacket,
  ) {
    var offset = 0;
    while (offset < data.length) {
      if (data[offset] & 0x80 == 0) {
        throw CryptoArgumentException('Invalid OpenPGP packet at offset $offset.');
      }
      final isNewFormat = (data[offset] & 0x40) != 0;
      int tag;
      int bodyLength;
      int headerLength;
      if (isNewFormat) {
        tag = data[offset] & 0x3F;
        final len = _readNewFormatLength(data, offset + 1);
        bodyLength = len.length;
        headerLength = 1 + len.bytesRead;
      } else {
        tag = (data[offset] & 0x3F) >> 2;
        final lengthType = data[offset] & 0x03;
        final len = _readOldFormatLength(data, offset + 1, lengthType);
        bodyLength = len.length;
        headerLength = 1 + len.bytesRead;
      }
      final bodyStart = offset + headerLength;
      final bodyEnd = bodyStart + bodyLength;
      if (bodyEnd > data.length) {
        throw CryptoArgumentException('Truncated OpenPGP packet (tag $tag).');
      }
      onPacket(tag, Uint8List.sublistView(data, bodyStart, bodyEnd));
      offset = bodyEnd;
    }
  }

  static ({int length, int bytesRead}) _readNewFormatLength(Uint8List data, int offset) {
    final first = data[offset];
    if (first < 192) return (length: first, bytesRead: 1);
    if (first < 224) {
      final length = ((first - 192) << 8) + data[offset + 1] + 192;
      return (length: length, bytesRead: 2);
    }
    if (first == 255) {
      final length = (data[offset + 1] << 24) |
          (data[offset + 2] << 16) |
          (data[offset + 3] << 8) |
          data[offset + 4];
      return (length: length, bytesRead: 5);
    }
    throw CryptoArgumentException('Unsupported OpenPGP partial body length.');
  }

  static ({int length, int bytesRead}) _readOldFormatLength(
    Uint8List data,
    int offset,
    int lengthType,
  ) {
    switch (lengthType) {
      case 0:
        return (length: data[offset], bytesRead: 1);
      case 1:
        return (length: (data[offset] << 8) | data[offset + 1], bytesRead: 2);
      case 2:
        return (
          length: (data[offset] << 24) |
              (data[offset + 1] << 16) |
              (data[offset + 2] << 8) |
              data[offset + 3],
          bytesRead: 4,
        );
      default:
        throw const CryptoArgumentException('Unsupported indeterminate-length packet.');
    }
  }
}
