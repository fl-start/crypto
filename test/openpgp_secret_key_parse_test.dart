import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hashes;
import 'package:cryptography/cryptography.dart' as pkg_crypto;
import 'package:test/test.dart';
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

const _oidEd25519 = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
const _oidCurve25519 = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

/// New-format OpenPGP packet with a single-byte body length (< 192 bytes).
Uint8List _packet(int tag, Uint8List body) {
  if (body.length >= 192) {
    throw ArgumentError('Test helper only supports bodies < 192 bytes.');
  }
  return Uint8List.fromList([0xC0 | tag, body.length, ...body]);
}

Uint8List _mpi(Uint8List bytes) {
  // Trim leading zero bytes (MPI bit-length is exact, not byte-padded),
  // matching how real OpenPGP implementations encode these fields.
  var trimmed = bytes;
  var leadingZeroBits = 0;
  var i = 0;
  while (i < trimmed.length && trimmed[i] == 0) {
    i++;
  }
  if (i > 0) trimmed = Uint8List.sublistView(trimmed, i);
  if (trimmed.isNotEmpty) {
    var b = trimmed[0];
    while (b != 0 && (b & 0x80) == 0) {
      leadingZeroBits++;
      b <<= 1;
    }
  }
  final bitLength = trimmed.length * 8 - leadingZeroBits;
  return Uint8List.fromList([
    (bitLength >> 8) & 0xFF,
    bitLength & 0xFF,
    ...trimmed,
  ]);
}

Uint8List _cfbEncryptAes(Uint8List key, Uint8List iv, Uint8List plaintext) {
  // Mirror of the parser's CFB decrypt, used only to build the test fixture
  // (encrypt with the real `cryptography` AesCtr-independent path isn't
  // available for CFB, so this test reuses the SDK's own AES core via its
  // public decrypt path in reverse is not exposed — instead we implement
  // encryption directly here with the same primitive shape as RFC 4880).
  final aes = _TestAesEncryptOnly(key);
  final out = Uint8List(plaintext.length);
  var feedback = iv;
  var offset = 0;
  while (offset < plaintext.length) {
    final blockLen = (plaintext.length - offset) >= 16 ? 16 : plaintext.length - offset;
    final keystream = aes.encryptBlock(feedback);
    for (var i = 0; i < blockLen; i++) {
      out[offset + i] = plaintext[offset + i] ^ keystream[i];
    }
    feedback = Uint8List.sublistView(out, offset, offset + blockLen);
    offset += blockLen;
  }
  return out;
}

Future<Uint8List> _deriveKeySimpleSha256(String passphrase) async {
  final digest = hashes.sha256.convert(utf8.encode(passphrase));
  return Uint8List.fromList(digest.bytes);
}

Uint8List _secretKeyPacketBody({
  required int algorithmId,
  required List<int> oid,
  required Uint8List publicPointWithPrefix,
  Uint8List? kdfParams,
  required Uint8List scalar,
  required Uint8List aesKey,
  required Uint8List iv,
  required int s2kHashAlgo,
}) {
  final publicPart = <int>[
    4, // version
    0, 0, 0, 0, // creation time
    algorithmId,
    oid.length,
    ...oid,
    ..._mpi(publicPointWithPrefix),
    ...?kdfParams,
  ];

  final scalarMpi = _mpi(scalar);
  final checksum = hashes.sha1.convert(scalarMpi).bytes;
  final toEncrypt = Uint8List.fromList([...scalarMpi, ...checksum]);
  final encrypted = _cfbEncryptAes(aesKey, iv, toEncrypt);

  final secretPart = <int>[
    254, // s2k usage: sha1-checked, encrypted
    9, // symmetric algo: AES-256
    0, // s2k type: simple
    s2kHashAlgo,
    ...iv,
    ...encrypted,
  ];

  return Uint8List.fromList([...publicPart, ...secretPart]);
}

void main() {
  group('OpenPgpSecretKeyParser', () {
    test('recovers a legacy-EdDSA primary signing seed', () async {
      const passphrase = 'correct horse battery staple';
      final seed = Uint8List.fromList(List.generate(32, (i) => (i * 7 + 3) % 256));
      final keyPair = await pkg_crypto.Ed25519().newKeyPairFromSeed(seed);
      final publicKey = await keyPair.extractPublicKey();
      final aesKey = await _deriveKeySimpleSha256(passphrase);
      final iv = Uint8List.fromList(List.generate(16, (i) => i));

      final body = _secretKeyPacketBody(
        algorithmId: 22,
        oid: _oidEd25519,
        publicPointWithPrefix: Uint8List.fromList([0x40, ...publicKey.bytes]),
        scalar: seed,
        aesKey: aesKey,
        iv: iv,
        s2kHashAlgo: 8, // SHA-256
      );
      final packetBytes = _packet(5, body);

      final extracted = await OpenPgpSecretKeyParser.extractPrimaryEd25519Seed(
        packetBytes,
        passphrase: passphrase,
      );

      expect(extracted, equals(seed));
    });

    test('recovers a legacy-ECDH (Curve25519) subkey scalar stored byte-reversed', () async {
      // GnuPG/gopenpgp store legacy ECDH-over-Curve25519 scalars and public
      // points MPI-wrapped in big-endian order — the reverse of the
      // little-endian encoding `package:cryptography`'s X25519 uses
      // natively. Build a fixture in that real-world wire convention and
      // confirm the parser recovers the *native* scalar (usable directly
      // for ECDH), not the wire-order bytes.
      const passphrase = 'correct horse battery staple';
      final nativeSeed = Uint8List.fromList(List.generate(32, (i) => (i * 11 + 5) % 256));
      final keyPair = await pkg_crypto.X25519().newKeyPairFromSeed(nativeSeed);
      final nativePublicKey = await keyPair.extractPublicKey();

      final wireScalar = Uint8List.fromList(nativeSeed.reversed.toList());
      final wirePoint = Uint8List.fromList(nativePublicKey.bytes.reversed.toList());

      final aesKey = await _deriveKeySimpleSha256(passphrase);
      final iv = Uint8List.fromList(List.generate(16, (i) => i));

      final body = _secretKeyPacketBody(
        algorithmId: 18,
        oid: _oidCurve25519,
        publicPointWithPrefix: Uint8List.fromList([0x40, ...wirePoint]),
        kdfParams: Uint8List.fromList([3, 1, 8, 7]),
        scalar: wireScalar,
        aesKey: aesKey,
        iv: iv,
        s2kHashAlgo: 8,
      );
      final packetBytes = _packet(7, body);

      final extracted = await OpenPgpSecretKeyParser.extractEncryptionSubkey(
        packetBytes,
        passphrase: passphrase,
      );

      expect(extracted.algorithmId, 18);
      expect(extracted.isSubKey, isTrue);
      expect(extracted.scalar, equals(nativeSeed));
      expect(extracted.publicKey, equals(wirePoint));

      // The recovered scalar must actually work for ECDH: deriving with it
      // natively must reproduce the same shared secret a peer would get
      // deriving against the OpenPGP-stored (wire-order) public point after
      // the standard byte-reversal conversion — i.e. the recovered scalar
      // is the true native private key, not a decoy that merely satisfies
      // the parser's own self-check.
      final peer = await pkg_crypto.X25519().newKeyPair();
      final peerPublic = await peer.extractPublicKey();
      final sharedViaRecoveredScalar = await pkg_crypto.X25519().sharedSecretKey(
        keyPair: await pkg_crypto.X25519().newKeyPairFromSeed(extracted.scalar),
        remotePublicKey: peerPublic,
      );
      final sharedViaOriginalSeed = await pkg_crypto.X25519().sharedSecretKey(
        keyPair: keyPair,
        remotePublicKey: peerPublic,
      );
      expect(
        await sharedViaRecoveredScalar.extractBytes(),
        equals(await sharedViaOriginalSeed.extractBytes()),
      );
    });

    test('rejects a wrong passphrase instead of returning bad key material', () async {
      const passphrase = 'right passphrase';
      final seed = Uint8List.fromList(List.generate(32, (i) => i));
      final keyPair = await pkg_crypto.Ed25519().newKeyPairFromSeed(seed);
      final publicKey = await keyPair.extractPublicKey();
      final aesKey = await _deriveKeySimpleSha256(passphrase);
      final iv = Uint8List.fromList(List.generate(16, (i) => i));

      final body = _secretKeyPacketBody(
        algorithmId: 22,
        oid: _oidEd25519,
        publicPointWithPrefix: Uint8List.fromList([0x40, ...publicKey.bytes]),
        scalar: seed,
        aesKey: aesKey,
        iv: iv,
        s2kHashAlgo: 8,
      );
      final packetBytes = _packet(5, body);

      expect(
        () => OpenPgpSecretKeyParser.extractPrimaryEd25519Seed(
          packetBytes,
          passphrase: 'wrong passphrase',
        ),
        throwsA(isA<KeyImportException>()),
      );
    });
  });
}

/// Test-only AES encryptor, structurally identical to the SDK's internal
/// one, used solely to build CFB-encrypted fixtures for the tests above.
class _TestAesEncryptOnly {
  final List<Uint32List> _roundKeys;
  final int _rounds;

  _TestAesEncryptOnly(Uint8List key)
      : _rounds = switch (key.length) {
          16 => 10,
          24 => 12,
          32 => 14,
          _ => throw ArgumentError('bad key length'),
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
