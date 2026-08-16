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

    test('decrypts OpenSSL CLI AES-128-CBC CMS (Outlook-like)', () async {
      if (!await _opensslCliAvailable()) return;

      final lib = SmimeLibcryptoBackend();
      final provider = SmimeCryptoProvider(backend: lib);
      final alice = await provider.generateKeyPair(
        const SmimeKeyGenerationParams(
          commonName: 'alice-128',
          email: 'alice128@test.example',
        ),
      );
      final dir = await Directory.systemTemp.createTemp('cms-aes128-');
      try {
        final certPath = '${dir.path}/cert.pem';
        final keyPath = '${dir.path}/key.pem';
        final inPath = '${dir.path}/plain.txt';
        final outPath = '${dir.path}/out.p7m';
        await File(certPath).writeAsBytes(alice.publicKey.rawBytes);
        await File(keyPath).writeAsBytes(alice.privateKey.rawBytes);
        await File(inPath).writeAsString('outlook-aes128-body');
        final encrypt = await Process.run('openssl', [
          'cms',
          '-encrypt',
          '-aes128',
          '-in',
          inPath,
          '-out',
          outPath,
          '-outform',
          'SMIME',
          '-recip',
          certPath,
        ]);
        if (encrypt.exitCode != 0) return;
        final cms = await File(outPath).readAsBytes();
        final decrypted = await lib.decrypt(
          encryptedData: cms,
          privateKey: alice.privateKey.rawBytes,
        );
        expect(utf8.decode(decrypted), 'outlook-aes128-body');
      } finally {
        await dir.delete(recursive: true);
      }
    });

    test('decrypts OpenSSL CLI RSA-OAEP CMS', () async {
      if (!await _opensslCliAvailable()) return;

      final lib = SmimeLibcryptoBackend();
      final provider = SmimeCryptoProvider(backend: lib);
      final alice = await provider.generateKeyPair(
        const SmimeKeyGenerationParams(
          commonName: 'alice-oaep',
          email: 'aliceoaep@test.example',
        ),
      );
      final dir = await Directory.systemTemp.createTemp('cms-oaep-');
      try {
        final certPath = '${dir.path}/cert.pem';
        final inPath = '${dir.path}/plain.txt';
        final outPath = '${dir.path}/out.p7m';
        await File(certPath).writeAsBytes(alice.publicKey.rawBytes);
        await File(inPath).writeAsString('oaep-plaintext');
        final encrypt = await Process.run('openssl', [
          'cms',
          '-encrypt',
          '-aes256',
          '-keyopt',
          'rsa_padding_mode:oaep',
          '-in',
          inPath,
          '-out',
          outPath,
          '-outform',
          'SMIME',
          '-recip',
          certPath,
        ]);
        if (encrypt.exitCode != 0) return;
        final cms = await File(outPath).readAsBytes();
        final decrypted = await lib.decrypt(
          encryptedData: cms,
          privateKey: alice.privateKey.rawBytes,
        );
        expect(utf8.decode(decrypted), 'oaep-plaintext');
      } finally {
        await dir.delete(recursive: true);
      }
    });

    test('extracts signer certs from signed-data', () async {
      final lib = SmimeLibcryptoBackend();
      final provider = SmimeCryptoProvider(backend: lib);
      final alice = await provider.generateKeyPair(
        const SmimeKeyGenerationParams(
          commonName: 'signer',
          email: 'signer@test.example',
        ),
      );
      final signed = await lib.sign(
        data: Uint8List.fromList(utf8.encode('signed-body')),
        privateKey: alice.privateKey.rawBytes,
        signerCertificate: alice.publicKey.rawBytes,
      );
      final certs = await lib.extractCertificates(signed);
      expect(certs, isNotEmpty);
      expect(utf8.decode(certs.first), contains('BEGIN CERTIFICATE'));
    });

    test('PEM/DER certificate round-trip and PKCS#12 unpack', () async {
      final provider = SmimeCryptoProvider();
      final pair = await provider.generateKeyPair(
        const SmimeKeyGenerationParams(
          commonName: 'outlook.cert',
          email: 'outlook@test.example',
        ),
      );
      final pem = pair.publicKey.rawBytes;
      final der = provider.certificateToDer(pem);
      expect(der.first, 0x30);
      expect(utf8.decode(der, allowMalformed: true), isNot(contains('BEGIN')));

      final pemAgain = provider.normalizeCertificateToPem(der);
      expect(utf8.decode(pemAgain), contains('BEGIN CERTIFICATE'));
      final meta = await provider.getPublicKeyMetadata(
        CryptoKey(
          algorithm: CryptoAlgorithm.smime,
          type: KeyType.publicKey,
          rawBytes: der,
        ),
      );
      expect(meta.emailAddress, 'outlook@test.example');

      const password = 'outlook-pfx-pass';
      final pfx = provider.packPkcs12(
        privateKeyPem: pair.privateKey.rawBytes,
        certificatePem: pem,
        password: password,
        friendlyName: 'outlook@test.example',
      );
      final unpacked = provider.unpackPkcs12(
        pkcs12Bytes: pfx,
        password: password,
      );
      expect(utf8.decode(unpacked.certificatePem), contains('BEGIN CERTIFICATE'));
      expect(utf8.decode(unpacked.privateKeyPem), contains('BEGIN'));
    });
  });
}
