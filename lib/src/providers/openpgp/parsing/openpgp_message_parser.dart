import 'dart:convert';
import 'dart:typed_data';

import '../../../core/exceptions/crypto_exceptions.dart';
import '../../../core/models/encrypted_message_metadata.dart';

/// Pure-Dart parser for OpenPGP encrypted messages (RFC 4880).
///
/// Extracts PKESK (tag 1) and SKESK (tag 3) packets plus non-secret
/// structural metadata from armored or binary ciphertext.
class OpenPgpMessageParser {
  const OpenPgpMessageParser._();

  /// Parses [ciphertext] and returns structured metadata.
  ///
  /// [ciphertext] may be UTF-8 ASCII-armored (`-----BEGIN PGP MESSAGE-----`)
  /// or raw binary OpenPGP packet data.
  static OpenPgpEncryptedMessageMetadata parse(Uint8List ciphertext) {
    final text = _looksArmored(ciphertext)
        ? utf8.decode(ciphertext, allowMalformed: true)
        : null;

    String? armorType;
    final Uint8List packetBytes;
    if (text != null) {
      final decoded = _decodeArmor(text);
      armorType = decoded.type;
      packetBytes = decoded.body;
    } else {
      packetBytes = ciphertext;
    }

    final pkesks = <PkeskEntry>[];
    final skesks = <SkeskEntry>[];
    final packetTags = <int>[];
    int? symmetricCipherAlgorithm;

    _forEachPacket(packetBytes, (tag, body) {
      packetTags.add(tag);
      switch (tag) {
        case 1:
          pkesks.add(_parsePkesk(body));
        case 3:
          skesks.add(_parseSkesk(body));
        case 18:
          symmetricCipherAlgorithm ??= _parseSeipdCipher(body);
        case 9:
          // Legacy symmetrically encrypted data — cipher not in packet header.
          break;
        default:
          break;
      }
    });

    return OpenPgpEncryptedMessageMetadata(
      armorType: armorType,
      pkesks: pkesks,
      skesks: skesks,
      symmetricCipherAlgorithm: symmetricCipherAlgorithm,
      symmetricCipherAlgorithmName: symmetricCipherAlgorithm == null
          ? null
          : _symmetricAlgorithmName(symmetricCipherAlgorithm!),
      packetTags: packetTags,
    );
  }

  static bool _looksArmored(Uint8List data) {
    if (data.length < 27) return false;
    const marker = '-----BEGIN PGP';
    final prefix = utf8.decode(data.sublist(0, 27), allowMalformed: true);
    return prefix.startsWith(marker);
  }

  static ({String type, Uint8List body}) _decodeArmor(String armored) {
    final beginRe = RegExp(
      r'-----BEGIN PGP ([A-Z ]+?)-----\s*\r?\n',
      multiLine: true,
    );
    final beginMatch = beginRe.firstMatch(armored);
    if (beginMatch == null) {
      throw const CryptoArgumentException(
        'Invalid OpenPGP armor: missing BEGIN header.',
      );
    }

    final type = beginMatch.group(1)!.trim();
    final bodyStart = beginMatch.end;

    final endMarker = '-----END PGP $type-----';
    final endIndex = armored.indexOf(endMarker, bodyStart);
    if (endIndex < 0) {
      throw CryptoArgumentException(
        'Invalid OpenPGP armor: missing END header for "$type".',
      );
    }

    final bodySection = armored.substring(bodyStart, endIndex);
    final b64Lines = bodySection
        .split(RegExp(r'\r?\n'))
        .map((line) => line.trim())
        .where(_isArmorBase64Line)
        .join();

    if (b64Lines.isEmpty) {
      throw const CryptoArgumentException(
        'Invalid OpenPGP armor: no base64 payload found.',
      );
    }

    try {
      return (type: type, body: base64Decode(b64Lines));
    } on FormatException catch (e) {
      throw CryptoArgumentException('Invalid OpenPGP armor base64: $e');
    }
  }

  /// True for lines that are part of the RFC 4880 armor base64 payload.
  ///
  /// Skips armor headers such as `Version: openpgp-mobile` and the `=` CRC line.
  static bool _isArmorBase64Line(String line) {
    if (line.isEmpty) return false;
    if (line.startsWith('=')) return false;
    return RegExp(r'^[A-Za-z0-9+/]+=*$').hasMatch(line);
  }

  static void _forEachPacket(
    Uint8List data,
    void Function(int tag, Uint8List body) onPacket,
  ) {
    var offset = 0;
    while (offset < data.length) {
      if (data[offset] & 0x80 == 0) {
        throw CryptoArgumentException(
          'Invalid OpenPGP packet at offset $offset: bit 7 not set.',
        );
      }

      final isNewFormat = (data[offset] & 0x40) != 0;
      late int tag;
      late int bodyLength;
      late int headerLength;

      if (isNewFormat) {
        tag = data[offset] & 0x3F;
        final lengthResult = _readNewFormatLength(data, offset + 1);
        bodyLength = lengthResult.length;
        headerLength = 1 + lengthResult.bytesRead;
      } else {
        tag = (data[offset] & 0x3F) >> 2;
        final lengthType = data[offset] & 0x03;
        final lengthResult = _readOldFormatLength(data, offset + 1, lengthType);
        bodyLength = lengthResult.length;
        headerLength = 1 + lengthResult.bytesRead;
      }

      final bodyStart = offset + headerLength;
      final bodyEnd = bodyStart + bodyLength;
      if (bodyEnd > data.length) {
        throw CryptoArgumentException(
          'Truncated OpenPGP packet (tag $tag) at offset $offset.',
        );
      }

      onPacket(tag, Uint8List.sublistView(data, bodyStart, bodyEnd));
      offset = bodyEnd;
    }
  }

  static ({int length, int bytesRead}) _readNewFormatLength(
    Uint8List data,
    int offset,
  ) {
    if (offset >= data.length) {
      throw const CryptoArgumentException('Truncated OpenPGP packet length.');
    }

    final first = data[offset];
    if (first < 192) {
      return (length: first, bytesRead: 1);
    }
    if (first < 224) {
      if (offset + 1 >= data.length) {
        throw const CryptoArgumentException('Truncated OpenPGP packet length.');
      }
      final length = ((first - 192) << 8) + data[offset + 1] + 192;
      return (length: length, bytesRead: 2);
    }
    if (first == 255) {
      if (offset + 4 >= data.length) {
        throw const CryptoArgumentException('Truncated OpenPGP packet length.');
      }
      final length = (data[offset + 1] << 24) |
          (data[offset + 2] << 16) |
          (data[offset + 3] << 8) |
          data[offset + 4];
      return (length: length, bytesRead: 5);
    }

    throw CryptoArgumentException(
      'Unsupported OpenPGP partial body length encoding ($first).',
    );
  }

  static ({int length, int bytesRead}) _readOldFormatLength(
    Uint8List data,
    int offset,
    int lengthType,
  ) {
    switch (lengthType) {
      case 0:
        if (offset >= data.length) {
          throw const CryptoArgumentException('Truncated OpenPGP packet length.');
        }
        return (length: data[offset], bytesRead: 1);
      case 1:
        if (offset + 1 >= data.length) {
          throw const CryptoArgumentException('Truncated OpenPGP packet length.');
        }
        return (
          length: (data[offset] << 8) | data[offset + 1],
          bytesRead: 2,
        );
      case 2:
        if (offset + 3 >= data.length) {
          throw const CryptoArgumentException('Truncated OpenPGP packet length.');
        }
        return (
          length: (data[offset] << 24) |
              (data[offset + 1] << 16) |
              (data[offset + 2] << 8) |
              data[offset + 3],
          bytesRead: 4,
        );
      default:
        throw const CryptoArgumentException(
          'Unsupported OpenPGP indeterminate-length packet.',
        );
    }
  }

  static PkeskEntry _parsePkesk(Uint8List body) {
    if (body.isEmpty) {
      throw const CryptoArgumentException('Empty PKESK packet body.');
    }

    final version = body[0];
    if (version != 3) {
      throw CryptoArgumentException('Unsupported PKESK version: $version.');
    }
    if (body.length < 10) {
      throw const CryptoArgumentException('Truncated PKESK packet body.');
    }

    final keyIdBytes = body.sublist(1, 9);
    final keyId = _formatKeyId(keyIdBytes);
    final publicKeyAlgorithm = body[9];
    final encryptedSessionKeyLength = body.length - 10;

    return PkeskEntry(
      version: version,
      keyId: keyId.full,
      keyIdShort: keyId.short,
      keyIdNumeric: keyId.numeric,
      publicKeyAlgorithm: publicKeyAlgorithm,
      publicKeyAlgorithmName: _publicKeyAlgorithmName(publicKeyAlgorithm),
      encryptedSessionKeyLength: encryptedSessionKeyLength,
    );
  }

  static SkeskEntry _parseSkesk(Uint8List body) {
    if (body.isEmpty) {
      throw const CryptoArgumentException('Empty SKESK packet body.');
    }

    final version = body[0];
    if (body.length < 3) {
      throw const CryptoArgumentException('Truncated SKESK packet body.');
    }

    final symmetricAlgorithm = body[1];
    final s2kType = body[2];

    return SkeskEntry(
      version: version,
      symmetricAlgorithm: symmetricAlgorithm,
      symmetricAlgorithmName: _symmetricAlgorithmName(symmetricAlgorithm),
      s2kType: s2kType,
      s2kTypeName: _s2kTypeName(s2kType),
    );
  }

  static int? _parseSeipdCipher(Uint8List body) {
    if (body.length < 2 || body[0] != 1) return null;
    return body[1];
  }

  static ({String full, String short, String numeric}) _formatKeyId(
    Uint8List keyIdBytes,
  ) {
    final full = keyIdBytes
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join()
        .toUpperCase();

    final shortBytes = keyIdBytes.length >= 4
        ? keyIdBytes.sublist(keyIdBytes.length - 4)
        : keyIdBytes;
    final short = shortBytes
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join()
        .toUpperCase();

    var numeric = BigInt.zero;
    for (final b in keyIdBytes) {
      numeric = (numeric << 8) | BigInt.from(b);
    }

    return (full: full, short: short, numeric: numeric.toString());
  }

  static String _publicKeyAlgorithmName(int id) {
    return switch (id) {
      1 => 'RSA (Encrypt or Sign)',
      2 => 'RSA (Encrypt-Only)',
      3 => 'RSA (Sign-Only)',
      16 => 'Elgamal',
      17 => 'DSA',
      18 => 'ECDH',
      19 => 'ECDSA',
      22 => 'EdDSA',
      _ => 'Unknown ($id)',
    };
  }

  static String _symmetricAlgorithmName(int id) {
    return switch (id) {
      0 => 'Plaintext',
      1 => 'IDEA',
      2 => 'TripleDES',
      3 => 'CAST5',
      4 => 'Blowfish',
      7 => 'AES-128',
      8 => 'AES-192',
      9 => 'AES-256',
      10 => 'Twofish',
      11 => 'Camellia-128',
      12 => 'Camellia-192',
      13 => 'Camellia-256',
      _ => 'Unknown ($id)',
    };
  }

  static String _s2kTypeName(int id) {
    return switch (id) {
      0 => 'Simple S2K',
      1 => 'Salted S2K',
      3 => 'Iterated and Salted S2K',
      101 => 'GnuPG-divert-to-card',
      102 => 'GnuPG-divert-to-card-with-s2k',
      _ => 'Unknown ($id)',
    };
  }
}
