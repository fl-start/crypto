import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hashes;
import 'package:cryptography/cryptography.dart' as pkg_crypto;

import '../../../core/exceptions/crypto_exceptions.dart';

/// Raw, algorithm-native key material recovered from an OpenPGP secret-key
/// or secret-subkey packet.
///
/// [scalar] is verified (see [OpenPgpSecretKeyParser]) to actually derive
/// the public key carried alongside it in the same packet, so callers can
/// trust it without re-deriving anything themselves.
class OpenPgpRawSecretKey {
  /// True for a secret-subkey packet (tag 7), false for the primary
  /// secret-key packet (tag 5).
  final bool isSubKey;

  /// OpenPGP public-key algorithm ID (RFC 4880 §9.1): 22 = EdDSA, 18 = ECDH.
  final int algorithmId;

  /// Raw little/big-endian-normalized 32-byte private scalar, already
  /// verified to derive [publicKey].
  final Uint8List scalar;

  /// Raw 32-byte native public key point (no OpenPGP 0x40 prefix, no MPI
  /// framing) — the same encoding `package:cryptography` produces.
  final Uint8List publicKey;

  const OpenPgpRawSecretKey({
    required this.isSubKey,
    required this.algorithmId,
    required this.scalar,
    required this.publicKey,
  });
}

const int _algoEddsaLegacy = 22;
const int _algoEcdh = 18;

// Raw OID octets (RFC 4880 §5.5.2 "curve OID" field content — NOT full ASN.1).
final Uint8List _oidEd25519Legacy = Uint8List.fromList(
  [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01],
);
final Uint8List _oidCurve25519Legacy = Uint8List.fromList(
  [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01],
);

/// Parses OpenPGP secret-key packets (tag 5) and secret-subkey packets
/// (tag 7) to recover the raw, algorithm-native private scalar underneath
/// the legacy EdDSA / ECDH-over-Curve25519 wrapping.
///
/// This exists solely because OpenPGP's own sign/decrypt operations sign or
/// decrypt in OpenPGP's own wire format (packet framing, hash trailers),
/// which is a different computation than a raw Ed25519 signature / raw
/// X25519 ECDH. Some callers (the SComm pubkey protocol) need the latter.
/// This parser does not implement or know about that protocol — it only
/// recovers key material, consistent with this package's role as an
/// OpenPGP *parser*, not a protocol client.
///
/// Every extracted scalar is verified by re-deriving its public key and
/// comparing it against the public key stored in the same packet. A parsing
/// or byte-order mistake therefore throws [KeyImportException] instead of
/// silently returning wrong key material.
class OpenPgpSecretKeyParser {
  const OpenPgpSecretKeyParser._();

  /// Parses every secret-key / secret-subkey packet in [privateKeyBytes]
  /// (armored or binary) and returns their recovered raw key material.
  ///
  /// [passphrase] decrypts S2K-protected secret material. Pass an empty
  /// string only if the key is known to be unprotected (S2K usage octet 0).
  static Future<List<OpenPgpRawSecretKey>> parseAll(
    Uint8List privateKeyBytes, {
    required String passphrase,
  }) async {
    final packetBytes = _unwrapArmorIfPresent(privateKeyBytes);
    // _forEachPacket's callback is synchronous, so packets are collected
    // first and parsed (async) afterwards, in order.
    final packets = <({int tag, Uint8List body})>[];
    _forEachPacket(packetBytes, (tag, body) {
      packets.add((tag: tag, body: body));
    });
    final results = <OpenPgpRawSecretKey>[];
    for (final packet in packets) {
      if (packet.tag != 5 && packet.tag != 7) continue;
      final parsed = await _parseSecretKeyPacket(
        packet.body,
        isSubKey: packet.tag == 7,
        passphrase: passphrase,
      );
      if (parsed != null) results.add(parsed);
    }
    return results;
  }

  /// Convenience: the primary key's raw Ed25519 signing seed.
  ///
  /// Throws [KeyImportException] if the primary key isn't legacy EdDSA, or
  /// if no primary secret-key packet is present.
  static Future<Uint8List> extractPrimaryEd25519Seed(
    Uint8List privateKeyBytes, {
    required String passphrase,
  }) async {
    final all = await parseAll(privateKeyBytes, passphrase: passphrase);
    final primary = all.firstWhere(
      (k) => !k.isSubKey,
      orElse: () => throw const KeyImportException(
        'No primary secret-key packet found.',
      ),
    );
    if (primary.algorithmId != _algoEddsaLegacy) {
      throw KeyImportException(
        'Primary key algorithm ${primary.algorithmId} is not legacy EdDSA '
        '(expected $_algoEddsaLegacy).',
      );
    }
    return primary.scalar;
  }

  /// Convenience: the raw X25519 scalar of the first legacy ECDH
  /// (Curve25519) secret-subkey packet — the encryption subkey a modern
  /// EdDSA/Curve25519 OpenPGP key carries alongside its Ed25519 primary key.
  ///
  /// The returned scalar is native little-endian X25519 (RFC 7748), already
  /// verified against the subkey's own public point — see [_verifyScalar].
  ///
  /// Throws [KeyImportException] if no ECDH secret-subkey packet is present.
  static Future<OpenPgpRawSecretKey> extractEncryptionSubkey(
    Uint8List privateKeyBytes, {
    required String passphrase,
  }) async {
    final all = await parseAll(privateKeyBytes, passphrase: passphrase);
    return all.firstWhere(
      (k) => k.isSubKey && k.algorithmId == _algoEcdh,
      orElse: () => throw const KeyImportException(
        'No ECDH (Curve25519) secret-subkey packet found.',
      ),
    );
  }

  // ── Armor handling ─────────────────────────────────────────────────────

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

  // ── Packet framing (RFC 4880 §4.2) ─────────────────────────────────────

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

  // ── Secret-key packet body (RFC 4880 §5.5.1.3, §5.5.3, §5.5.2, §11.2) ──

  static Future<OpenPgpRawSecretKey?> _parseSecretKeyPacket(
    Uint8List body, {
    required bool isSubKey,
    required String passphrase,
  }) async {
    var offset = 0;
    final version = body[offset++];
    if (version != 4) {
      throw KeyImportException('Unsupported secret-key packet version: $version (only v4 is supported).');
    }
    offset += 4; // creation time
    final algorithmId = body[offset++];
    if (algorithmId != _algoEddsaLegacy && algorithmId != _algoEcdh) {
      // Not a curve25519-family key (e.g. RSA) — nothing this extractor
      // supports; the caller's algorithm/purpose selection already ensures
      // we only reach here for ed25519/cv25519 keys in practice.
      return null;
    }

    final oidLen = body[offset++];
    final oid = body.sublist(offset, offset + oidLen);
    offset += oidLen;
    final expectedOid = algorithmId == _algoEddsaLegacy ? _oidEd25519Legacy : _oidCurve25519Legacy;
    if (!_bytesEqual(oid, expectedOid)) {
      throw KeyImportException('Unsupported curve OID for algorithm $algorithmId.');
    }

    final pointMpi = _readMpi(body, offset);
    offset = pointMpi.nextOffset;
    final publicPoint = _stripNativePointPrefix(pointMpi.bytes);

    if (algorithmId == _algoEcdh) {
      // KDF parameters: 1-byte length, then that many bytes (reserved, hash algo, sym algo).
      final kdfLen = body[offset++];
      offset += kdfLen;
    }

    final s2kUsage = body[offset++];
    Uint8List secretPlain;
    if (s2kUsage == 0) {
      secretPlain = body.sublist(offset);
    } else if (s2kUsage == 254 || s2kUsage == 255) {
      final symAlgo = body[offset++];
      final s2kType = body[offset++];
      final hashAlgo = body[offset++];
      Uint8List salt = Uint8List(0);
      if (s2kType == 1 || s2kType == 3) {
        salt = body.sublist(offset, offset + 8);
        offset += 8;
      }
      int? codedCount;
      if (s2kType == 3) {
        codedCount = body[offset++];
      }
      final ivLength = _blockSizeForCipher(symAlgo);
      final iv = body.sublist(offset, offset + ivLength);
      offset += ivLength;
      final encrypted = body.sublist(offset);

      final keyLength = _keyLengthForCipher(symAlgo);
      final sessionKey = await _deriveS2kKey(
        s2kType: s2kType,
        hashAlgo: hashAlgo,
        salt: salt,
        codedCount: codedCount,
        passphrase: passphrase,
        keyLength: keyLength,
      );
      final decrypted = _cfbDecryptAes(sessionKey, iv, encrypted);

      if (s2kUsage == 254) {
        if (decrypted.length < 20) {
          throw const KeyImportException('Truncated secret-key material (missing SHA-1 checksum).');
        }
        final material = decrypted.sublist(0, decrypted.length - 20);
        final checksum = decrypted.sublist(decrypted.length - 20);
        final actual = hashes.sha1.convert(material).bytes;
        if (!_bytesEqual(Uint8List.fromList(actual), checksum)) {
          throw const KeyImportException(
            'Secret-key checksum mismatch — wrong passphrase or corrupted key.',
          );
        }
        secretPlain = material;
      } else {
        if (decrypted.length < 2) {
          throw const KeyImportException('Truncated secret-key material (missing checksum).');
        }
        final material = decrypted.sublist(0, decrypted.length - 2);
        final checksumBytes = decrypted.sublist(decrypted.length - 2);
        final expectedChecksum = (checksumBytes[0] << 8) | checksumBytes[1];
        var sum = 0;
        for (final b in material) {
          sum = (sum + b) & 0xFFFF;
        }
        if (sum != expectedChecksum) {
          throw const KeyImportException(
            'Secret-key checksum mismatch — wrong passphrase or corrupted key.',
          );
        }
        secretPlain = material;
      }
    } else {
      throw KeyImportException('Unsupported S2K usage octet: $s2kUsage.');
    }

    final scalarMpi = _readMpi(secretPlain, 0);
    final rawScalar = _normalizeScalarLength(scalarMpi.bytes);

    final verified = await _verifyScalar(
      algorithmId: algorithmId,
      candidate: rawScalar,
      expectedPublicKey: publicPoint,
    );
    return OpenPgpRawSecretKey(
      isSubKey: isSubKey,
      algorithmId: algorithmId,
      scalar: verified,
      publicKey: publicPoint,
    );
  }

  // ── MPI helpers (RFC 4880 §3.2) ────────────────────────────────────────

  static ({Uint8List bytes, int nextOffset}) _readMpi(Uint8List data, int offset) {
    final bitLength = (data[offset] << 8) | data[offset + 1];
    final byteLength = (bitLength + 7) ~/ 8;
    final start = offset + 2;
    final bytes = data.sublist(start, start + byteLength);
    return (bytes: bytes, nextOffset: start + byteLength);
  }

  /// Legacy EdDSA/ECDH public points are MPI-wrapped `0x40 || rawPoint`.
  static Uint8List _stripNativePointPrefix(Uint8List mpiBytes) {
    if (mpiBytes.isNotEmpty && mpiBytes[0] == 0x40) {
      return Uint8List.sublistView(mpiBytes, 1);
    }
    return mpiBytes;
  }

  static Uint8List _normalizeScalarLength(Uint8List raw) {
    if (raw.length == 32) return raw;
    if (raw.length > 32) {
      // Leading zero padding from MPI bit-length rounding — trim from the
      // front (MPI is big-endian).
      return Uint8List.sublistView(raw, raw.length - 32);
    }
    final padded = Uint8List(32);
    padded.setRange(32 - raw.length, 32, raw);
    return padded;
  }

  // ── S2K key derivation (RFC 4880 §3.7) ─────────────────────────────────

  static Future<Uint8List> _deriveS2kKey({
    required int s2kType,
    required int hashAlgo,
    required Uint8List salt,
    required int? codedCount,
    required String passphrase,
    required int keyLength,
  }) async {
    final passBytes = Uint8List.fromList(utf8.encode(passphrase));
    final Uint8List seed;
    if (s2kType == 0) {
      seed = passBytes;
    } else if (s2kType == 1) {
      seed = Uint8List.fromList([...salt, ...passBytes]);
    } else if (s2kType == 3) {
      final count = (16 + (codedCount! & 15)) << ((codedCount >> 4) + 6);
      final unit = Uint8List.fromList([...salt, ...passBytes]);
      final builder = BytesBuilder();
      while (builder.length < count) {
        final remaining = count - builder.length;
        if (remaining >= unit.length) {
          builder.add(unit);
        } else {
          builder.add(unit.sublist(0, remaining));
        }
      }
      seed = builder.toBytes();
    } else {
      throw KeyImportException('Unsupported S2K type: $s2kType.');
    }

    final digestSize = _digestSizeForHash(hashAlgo);
    final contexts = (keyLength / digestSize).ceil();
    final out = BytesBuilder();
    for (var i = 0; i < contexts; i++) {
      final prefixed = Uint8List.fromList([...List.filled(i, 0), ...seed]);
      out.add(_hash(hashAlgo, prefixed));
    }
    final full = out.toBytes();
    return Uint8List.sublistView(full, 0, keyLength);
  }

  static Uint8List _hash(int hashAlgo, List<int> data) {
    switch (hashAlgo) {
      case 2:
        return Uint8List.fromList(hashes.sha1.convert(data).bytes);
      case 8:
        return Uint8List.fromList(hashes.sha256.convert(data).bytes);
      default:
        throw KeyImportException('Unsupported S2K hash algorithm: $hashAlgo.');
    }
  }

  static int _digestSizeForHash(int hashAlgo) {
    switch (hashAlgo) {
      case 2:
        return 20;
      case 8:
        return 32;
      default:
        throw KeyImportException('Unsupported S2K hash algorithm: $hashAlgo.');
    }
  }

  static int _keyLengthForCipher(int symAlgo) {
    switch (symAlgo) {
      case 7:
        return 16;
      case 8:
        return 24;
      case 9:
        return 32;
      default:
        throw KeyImportException('Unsupported symmetric-key algorithm: $symAlgo (only AES is supported).');
    }
  }

  static int _blockSizeForCipher(int symAlgo) {
    switch (symAlgo) {
      case 7:
      case 8:
      case 9:
        return 16; // AES block size regardless of key length.
      default:
        throw KeyImportException('Unsupported symmetric-key algorithm: $symAlgo (only AES is supported).');
    }
  }

  // ── CFB decryption over raw AES (RFC 4880 §5.5.3: plain CFB, no MDC prefix) ─

  static Uint8List _cfbDecryptAes(Uint8List key, Uint8List iv, Uint8List ciphertext) {
    return AesCfbRaw.decrypt(key: key, iv: iv, ciphertext: ciphertext);
  }

  // ── Self-verification: re-derive the public key from the scalar ───────

  static Future<Uint8List> _verifyScalar({
    required int algorithmId,
    required Uint8List candidate,
    required Uint8List expectedPublicKey,
  }) async {
    final asIs = await _derivedPublicKey(algorithmId, candidate);
    if (_bytesEqual(asIs, expectedPublicKey)) return candidate;

    final reversed = Uint8List.fromList(candidate.reversed.toList());
    final reversedDerived = await _derivedPublicKey(algorithmId, reversed);
    if (_bytesEqual(reversedDerived, expectedPublicKey)) return reversed;

    // Legacy ECDH-over-Curve25519 packets (RFC 4880 legacy profile, as
    // produced by GnuPG/gopenpgp) store the MPI-wrapped scalar *and* public
    // point in big-endian byte order — the reverse of the little-endian
    // encoding X25519 implementations (this package included) use natively.
    // A full-array byte reversal is a pure serialization change, so the
    // native relation nativePub = X25519(nativeScalar) still holds once
    // both sides are converted: reverse(derive(reverse(storedScalar))) ==
    // storedPoint. Only the ECDH algorithm uses this convention — legacy
    // EdDSA (Ed25519) signing keys do not, so this branch is gated to avoid
    // ever returning byte-reversed material for a signing key.
    if (algorithmId == _algoEcdh) {
      final reversedDerivedThenReversed = Uint8List.fromList(
        reversedDerived.reversed.toList(),
      );
      if (_bytesEqual(reversedDerivedThenReversed, expectedPublicKey)) {
        return reversed;
      }
    }

    throw const KeyImportException(
      'Recovered secret scalar does not derive the expected public key '
      '(tried native, byte-reversed, and legacy ECDH encodings). Refusing '
      'to return unverified key material.',
    );
  }

  static Future<Uint8List> _derivedPublicKey(int algorithmId, Uint8List scalar) async {
    try {
      if (algorithmId == _algoEddsaLegacy) {
        final keyPair = await pkg_crypto.Ed25519().newKeyPairFromSeed(scalar);
        final pub = await keyPair.extractPublicKey();
        return Uint8List.fromList(pub.bytes);
      } else {
        final keyPair = await pkg_crypto.X25519().newKeyPairFromSeed(scalar);
        final pub = await keyPair.extractPublicKey();
        return Uint8List.fromList(pub.bytes);
      }
    } catch (_) {
      // An invalid seed (e.g. wrong length after a bad parse) — treat as a
      // verification failure, not a crash.
      return Uint8List(0);
    }
  }

  static bool _bytesEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

/// Minimal, dependency-free CFB-128 decryption over raw AES.
///
/// OpenPGP secret-key protection uses plain CFB (full block feedback, no
/// resync prefix) — this is deliberately not `package:cryptography`'s
/// `AesCtr`/`AesGcm` (neither is CFB) and not a new external dependency;
/// it implements CFB decryption on top of a from-scratch, constant-shape
/// AES-128/192/256 single-block encryptor (encryption only — CFB
/// decryption never calls AES decrypt).
class AesCfbRaw {
  const AesCfbRaw._();

  static Uint8List decrypt({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List ciphertext,
  }) {
    final aes = _AesEncryptOnly(key);
    final out = Uint8List(ciphertext.length);
    var feedback = iv;
    var offset = 0;
    while (offset < ciphertext.length) {
      final blockLen = (ciphertext.length - offset) >= 16 ? 16 : ciphertext.length - offset;
      final keystream = aes.encryptBlock(feedback);
      for (var i = 0; i < blockLen; i++) {
        out[offset + i] = ciphertext[offset + i] ^ keystream[i];
      }
      // CFB is a stream mode: a shorter final block is valid (only that
      // many keystream bytes are consumed). Feedback for the next block is
      // always the full ciphertext block just consumed, even on a partial
      // trailing block it wouldn't matter (nothing reads it afterwards).
      feedback = ciphertext.sublist(offset, offset + blockLen);
      offset += blockLen;
    }
    return out;
  }
}

/// From-scratch AES (FIPS-197) block encryption, key sizes 128/192/256.
///
/// Only encryption is implemented — CFB mode only ever needs the AES
/// *encrypt* direction, even when the surrounding stream is being
/// decrypted.
class _AesEncryptOnly {
  final List<Uint32List> _roundKeys;
  final int _rounds;

  _AesEncryptOnly(Uint8List key)
      : _rounds = switch (key.length) {
          16 => 10,
          24 => 12,
          32 => 14,
          _ => throw CryptoArgumentException('Invalid AES key length: ${key.length}'),
        },
        _roundKeys = _expandKey(key);

  Uint8List encryptBlock(Uint8List input) {
    final state = Uint8List.fromList(input.sublist(0, 16));
    _addRoundKey(state, _roundKeys[0]);
    for (var round = 1; round < _rounds; round++) {
      _subBytes(state);
      _shiftRows(state);
      _mixColumns(state);
      _addRoundKey(state, _roundKeys[round]);
    }
    _subBytes(state);
    _shiftRows(state);
    _addRoundKey(state, _roundKeys[_rounds]);
    return state;
  }

  static void _addRoundKey(Uint8List state, Uint32List roundKey) {
    for (var c = 0; c < 4; c++) {
      final w = roundKey[c];
      state[c * 4 + 0] ^= (w >> 24) & 0xFF;
      state[c * 4 + 1] ^= (w >> 16) & 0xFF;
      state[c * 4 + 2] ^= (w >> 8) & 0xFF;
      state[c * 4 + 3] ^= w & 0xFF;
    }
  }

  static void _subBytes(Uint8List state) {
    for (var i = 0; i < 16; i++) {
      state[i] = _sbox[state[i]];
    }
  }

  static void _shiftRows(Uint8List state) {
    // state is column-major: state[col*4 + row]
    final t = Uint8List.fromList(state);
    for (var row = 1; row < 4; row++) {
      for (var col = 0; col < 4; col++) {
        state[col * 4 + row] = t[((col + row) % 4) * 4 + row];
      }
    }
  }

  static int _xtime(int a) => ((a << 1) ^ (((a >> 7) & 1) * 0x1B)) & 0xFF;

  static void _mixColumns(Uint8List state) {
    for (var c = 0; c < 4; c++) {
      final a0 = state[c * 4 + 0];
      final a1 = state[c * 4 + 1];
      final a2 = state[c * 4 + 2];
      final a3 = state[c * 4 + 3];
      final r0 = _xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3;
      final r1 = a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3;
      final r2 = a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3);
      final r3 = (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3);
      state[c * 4 + 0] = r0 & 0xFF;
      state[c * 4 + 1] = r1 & 0xFF;
      state[c * 4 + 2] = r2 & 0xFF;
      state[c * 4 + 3] = r3 & 0xFF;
    }
  }

  static List<Uint32List> _expandKey(Uint8List key) {
    final nk = key.length ~/ 4;
    final rounds = switch (nk) { 4 => 10, 6 => 12, 8 => 14, _ => throw ArgumentError(nk) };
    final totalWords = 4 * (rounds + 1);
    final w = Uint32List(totalWords);
    for (var i = 0; i < nk; i++) {
      w[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
    }
    for (var i = nk; i < totalWords; i++) {
      var temp = w[i - 1];
      if (i % nk == 0) {
        temp = _subWord(_rotWord(temp)) ^ (_rcon[i ~/ nk] << 24);
      } else if (nk > 6 && i % nk == 4) {
        temp = _subWord(temp);
      }
      w[i] = w[i - nk] ^ temp;
    }
    final roundKeys = <Uint32List>[];
    for (var r = 0; r <= rounds; r++) {
      roundKeys.add(Uint32List.fromList(w.sublist(r * 4, r * 4 + 4)));
    }
    return roundKeys;
  }

  static int _rotWord(int w) => ((w << 8) | (w >> 24)) & 0xFFFFFFFF;

  static int _subWord(int w) {
    return (_sbox[(w >> 24) & 0xFF] << 24) |
        (_sbox[(w >> 16) & 0xFF] << 16) |
        (_sbox[(w >> 8) & 0xFF] << 8) |
        _sbox[w & 0xFF];
  }

  static const List<int> _rcon = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D,
  ];

  static const List<int> _sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
  ];
}
