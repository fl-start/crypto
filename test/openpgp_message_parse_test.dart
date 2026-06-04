import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

/// Builds a new-format OpenPGP packet with a single-byte body length.
Uint8List _packet(int tag, Uint8List body) {
  if (body.length >= 192) {
    throw ArgumentError('Test helper only supports bodies < 192 bytes.');
  }
  return Uint8List.fromList([0xC0 | tag, body.length, ...body]);
}

/// Builds a minimal encrypted-message packet stream: PKESK + SEIPD stub.
Uint8List _syntheticEncryptedMessage({
  required List<int> keyIdBytes,
  required int publicKeyAlgorithm,
  int symmetricCipher = 9,
}) {
  final pkeskBody = Uint8List.fromList([
    0x03, // version 3
    ...keyIdBytes,
    publicKeyAlgorithm,
    ...List.filled(16, 0xAA), // dummy encrypted session key
  ]);

  final seipdBody = Uint8List.fromList([
    0x01, // SEIPD version 1
    symmetricCipher,
    ...List.filled(32, 0xBB), // dummy encrypted payload
  ]);

  return Uint8List.fromList([
    ..._packet(1, pkeskBody),
    ..._packet(18, seipdBody),
  ]);
}

String _armor(Uint8List binary, {String type = 'MESSAGE', String? version}) {
  final b64 = base64Encode(binary);
  final buffer = StringBuffer()
    ..writeln('-----BEGIN PGP $type-----');
  if (version != null) {
    buffer.writeln('Version: $version');
  }
  buffer
    ..writeln(b64)
    ..writeln('-----END PGP $type-----');
  return buffer.toString();
}

void main() {
  group('OpenPgpPublicKeyMetadata', () {
    test('allKeyIds includes primary and subkey IDs', () {
      final meta = OpenPgpPublicKeyMetadata.fromMap({
        'algorithm': 'EdDSA',
        'keyId': '950A7F53D8F370B4',
        'keyIdShort': 'D8F370B4',
        'subKeys': [
          {
            'algorithm': 'ECDH',
            'keyId': '2B9481B91CFB911D',
            'keyIdShort': '1CFB911D',
            'isSubKey': true,
            'canEncrypt': true,
          },
        ],
      });

      expect(meta.allKeyIds, ['950A7F53D8F370B4', '2B9481B91CFB911D']);
      expect(meta.allKeyIdsShort, ['D8F370B4', '1CFB911D']);
    });
  });

  group('OpenPgpMessageParser', () {
    test('extracts PKESK keyId and algorithm from binary packets', () {
      const keyId = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
      final binary = _syntheticEncryptedMessage(
        keyIdBytes: keyId,
        publicKeyAlgorithm: 18,
        symmetricCipher: 9,
      );

      final meta = OpenPgpMessageParser.parse(binary);

      expect(meta.armorType, isNull);
      expect(meta.packetTags, [1, 18]);
      expect(meta.pkesks, hasLength(1));

      final pkesk = meta.pkesks.first;
      expect(pkesk.version, 3);
      expect(pkesk.keyId, '0123456789ABCDEF');
      expect(pkesk.keyIdShort, '89ABCDEF');
      expect(pkesk.keyIdNumeric, '81985529216486895');
      expect(pkesk.publicKeyAlgorithm, 18);
      expect(pkesk.publicKeyAlgorithmName, 'ECDH');
      expect(pkesk.encryptedSessionKeyLength, 16);

      expect(meta.symmetricCipherAlgorithm, 9);
      expect(meta.symmetricCipherAlgorithmName, 'AES-256');
    });

    test('extracts multiple PKESK packets for multi-recipient messages', () {
      final pkesk1 = _packet(
        1,
        Uint8List.fromList([
          0x03,
          0xAA,
          0xAA,
          0xAA,
          0xAA,
          0xAA,
          0xAA,
          0xAA,
          0xAA,
          0x01, // RSA
          0x01,
        ]),
      );
      final pkesk2 = _packet(
        1,
        Uint8List.fromList([
          0x03,
          0xBB,
          0xBB,
          0xBB,
          0xBB,
          0xBB,
          0xBB,
          0xBB,
          0xBB,
          18, // ECDH (decimal, not 0x18)
          0x02,
        ]),
      );
      final seipd = _packet(18, Uint8List.fromList([0x01, 0x07, 0x00]));
      final binary = Uint8List.fromList([...pkesk1, ...pkesk2, ...seipd]);

      final meta = OpenPgpMessageParser.parse(binary);

      expect(meta.pkesks, hasLength(2));
      expect(meta.pkesks[0].keyId, 'AAAAAAAAAAAAAAAA');
      expect(meta.pkesks[0].publicKeyAlgorithmName, 'RSA (Encrypt or Sign)');
      expect(meta.pkesks[1].keyId, 'BBBBBBBBBBBBBBBB');
      expect(meta.pkesks[1].publicKeyAlgorithmName, 'ECDH');
      expect(meta.symmetricCipherAlgorithmName, 'AES-128');
      expect(meta.recipientKeyIds, ['AAAAAAAAAAAAAAAA', 'BBBBBBBBBBBBBBBB']);
    });

    test('parses ASCII-armored ciphertext', () {
      const keyId = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x01];
      final binary = _syntheticEncryptedMessage(
        keyIdBytes: keyId,
        publicKeyAlgorithm: 22,
      );
      final armored = utf8.encode(_armor(binary));

      final meta = OpenPgpMessageParser.parse(armored);

      expect(meta.armorType, 'MESSAGE');
      expect(meta.recipientKeyIds, ['DEADBEEF00000001']);
      expect(meta.pkesks.single.publicKeyAlgorithmName, 'EdDSA');
    });

    test('parses ASCII-armored ciphertext with Version header', () {
      const keyId = [0x41, 0x49, 0x9A, 0x2C, 0xE5, 0xCA, 0xA3, 0x24];
      final binary = _syntheticEncryptedMessage(
        keyIdBytes: keyId,
        publicKeyAlgorithm: 18,
      );
      final armored = utf8.encode(_armor(binary, version: 'openpgp-mobile'));

      final meta = OpenPgpMessageParser.parse(armored);

      expect(meta.armorType, 'MESSAGE');
      expect(meta.pkesks.single.keyId, '41499A2CE5CAA324');
    });

    test('throws on invalid armor', () {
      expect(
        () => OpenPgpMessageParser.parse(utf8.encode('not a pgp message')),
        throwsA(isA<CryptoArgumentException>()),
      );
    });
  });
}
