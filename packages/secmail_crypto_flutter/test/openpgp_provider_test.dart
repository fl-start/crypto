import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:openpgp/openpgp.dart';
import 'package:secmail_crypto_flutter/secmail_crypto_flutter.dart';
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

Uint8List _packet(int tag, Uint8List body) {
  return Uint8List.fromList([0xC0 | tag, body.length, ...body]);
}

void main() {
  group('OpenPgpCryptoProvider', () {
    late OpenPgpCryptoProvider provider;

    setUp(() {
      provider = OpenPgpCryptoProvider(poolSize: 1);
    });

    tearDown(() async {
      await provider.shutdown();
    });

    test('parseEncryptedMessage delegates to parser', () async {
      const keyId = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
      final pkeskBody = Uint8List.fromList([
        0x03,
        ...keyId,
        18,
        ...List.filled(16, 0xAA),
      ]);
      final seipdBody = Uint8List.fromList([0x01, 9, ...List.filled(32, 0xBB)]);
      final binary = Uint8List.fromList([
        ..._packet(1, pkeskBody),
        ..._packet(18, seipdBody),
      ]);

      final meta = await provider.parseEncryptedMessage(binary);

      expect(meta, isA<OpenPgpEncryptedMessageMetadata>());
      expect(meta.recipientKeyIds, ['1122334455667788']);
    });
  });

  group('SecmailCryptoFlutter.initialize', () {
    test('registers OpenPGP provider', () {
      CryptoSdk.reset();
      final sdk = SecmailCryptoFlutter.initialize();
      expect(sdk.hasProvider(CryptoAlgorithm.openPgp), isTrue);
      CryptoSdk.reset();
    });
  });
}
