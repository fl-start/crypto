import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';
import 'package:secmail_crypto_sdk/src/providers/smime/backend/smime_libcrypto_backend.dart';
import 'package:secmail_crypto_sdk/src/providers/smime/openssl/smime_openssl_engine.dart';
import 'package:test/test.dart';

Future<bool> _opensslCliAvailable() async {
  try {
    final result = await Process.run('openssl', ['version']);
    return result.exitCode == 0;
  } catch (_) {
    return false;
  }
}

void main() {
  group('SmimeLibcryptoBackend', () {
    test('detached RSA-SHA256 matches CLI engine', () async {
      if (!await _opensslCliAvailable()) return;

      final lib = SmimeLibcryptoBackend();
      final cli = SmimeOpensslEngine();
      final provider = SmimeCryptoProvider(backend: lib);
      final keyPair = await provider.generateKeyPair(
        const SmimeKeyGenerationParams(
          commonName: 'parity.test',
          email: 'parity@test.example',
        ),
      );

      const payload = 'parity-payload-123';
      final payloadBytes = Uint8List.fromList(utf8.encode(payload));
      final privateKey = keyPair.privateKey.rawBytes;

      final libSig = await lib.signDetachedRsaSha256(
        data: payloadBytes,
        privateKey: privateKey,
      );
      final cliSig = await cli.signDetachedRsaSha256(
        data: payloadBytes,
        privateKey: privateKey,
      );

      expect(libSig, isNotEmpty);
      expect(libSig.length, 256);
      expect(cliSig, isNotEmpty);
      expect(cliSig.length, 256);
    });

    test('CMS encrypt/decrypt round-trip', () async {
      final lib = SmimeLibcryptoBackend();
      final provider = SmimeCryptoProvider(backend: lib);
      final alice = await provider.generateKeyPair(
        const SmimeKeyGenerationParams(
          commonName: 'alice',
          email: 'alice@test.example',
        ),
      );
      final bob = await provider.generateKeyPair(
        const SmimeKeyGenerationParams(
          commonName: 'bob',
          email: 'bob@test.example',
        ),
      );

      const plaintext = 'hello libcrypto smime';
      final encrypted = await lib.encrypt(
        data: Uint8List.fromList(utf8.encode(plaintext)),
        certificates: [alice.publicKey.rawBytes, bob.publicKey.rawBytes],
      );
      final decryptedAlice = await lib.decrypt(
        encryptedData: encrypted,
        privateKey: alice.privateKey.rawBytes,
      );
      expect(utf8.decode(decryptedAlice), plaintext);
    });
  });
}
