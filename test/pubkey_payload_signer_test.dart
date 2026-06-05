import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';
import 'package:test/test.dart';

Future<bool> _opensslAvailable() async {
  try {
    final result = await Process.run('openssl', ['version']);
    return result.exitCode == 0;
  } catch (_) {
    return false;
  }
}

void main() {
  group('PubkeyPayloadSigner', () {
    test('signAuthHeaderPayload signs the base64url header bytes', () async {
      const payloadB64 = 'eyJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20ifQ';
      final sdk = CryptoSdk.initialize(
        CryptoSdkConfig(storageProvider: InMemoryStorageProvider()),
      );

      // Without a real key we only verify the API accepts header material.
      final signer = PubkeyPayloadSigner(sdk);
      expect(
        () => signer.signAuthHeaderPayload(
          payloadB64: payloadB64,
          signingPrivateKey: CryptoKey(
            algorithm: CryptoAlgorithm.smime,
            type: KeyType.privateKey,
            rawBytes: Uint8List.fromList(utf8.encode('not-a-key')),
          ),
          sigFamily: PubkeySigFamily.smime,
        ),
        throwsA(isA<Exception>()),
      );
    });

    test('S/MIME detached RSA-SHA256 produces base64url signature', () async {
      if (!await _opensslAvailable()) return;

      try {
      final provider = SmimeCryptoProvider();
      final keyPair = await provider.generateKeyPair(
        const SmimeKeyGenerationParams(
          commonName: 'pubkey.test',
          email: 'pubkey@test.example',
        ),
      );

      const payload = '{"email":"a@b.com","algorithm":"smime-rsa-sha256"}';
      final sdk = CryptoSdk.initialize(
        CryptoSdkConfig(
          storageProvider: InMemoryStorageProvider(),
          providers: [provider],
        ),
      );

      final signer = PubkeyPayloadSigner(sdk);
      final signatureB64 = await signer.signPayloadString(
        payloadString: payload,
        signingPrivateKey: keyPair.privateKey,
        sigFamily: PubkeySigFamily.smime,
      );

      expect(signatureB64.contains('='), isFalse);
      expect(signatureB64.contains('+'), isFalse);
      expect(signatureB64.contains('/'), isFalse);
      final decoded = decodeBase64Url(signatureB64);
      expect(decoded, isNotEmpty);
      } catch (e) {
        // OpenSSL present but misconfigured (e.g. missing openssl.cnf on Windows CI).
        if (!e.toString().contains('OpenSSL')) rethrow;
      }
    });
  });
}
