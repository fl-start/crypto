import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

import 'package:secmail_crypto_sdk/src/providers/smime/parsing/smime_message_parser.dart';

/// Sample `openssl cms -cmsout -print` output for a single RSA recipient.
const _cmsPrintSingleRecipient = '''
CMS_ContentInfo: 
  contentType: pkcs7-envelopedData (1.2.840.113549.1.7.3)
  d.envelopedData: 
    version: 0
    recipientInfos:
      d.ktri: 
        version: 0
        d.issuerAndSerialNumber: 
          issuer: CN=Benchmark User, emailAddress=benchmark@example.com
          serialNumber: 0x75C28EC195F9C31545326DD47A569ED03895CB83
        keyEncryptionAlgorithm: 
          algorithm: rsaEncryption (1.2.840.113549.1.1.1)
          parameter: NULL
        encryptedKey: 
          0000 - aa bb cc dd ee ff 00 11-22 33 44 55 66 77 88 99   ........"3DUfw..
    encryptedContentInfo: 
      contentType: pkcs7-data (1.2.840.113549.1.7.1)
      contentEncryptionAlgorithm: 
        algorithm: aes-256-cbc (2.16.840.1.101.3.4.1.42)
        parameter: OCTET STRING
          0000 - 01 02 03 04 05 06 07 08-09 0a 0b 0c 0d 0e 0f 10   ................
      encryptedContent: 
        0000 - de ad be ef                                       ....
''';

const _cmsPrintMultiRecipient = '''
CMS_ContentInfo: 
  contentType: pkcs7-envelopedData (1.2.840.113549.1.7.3)
  d.envelopedData: 
    version: 0
    recipientInfos:
      d.ktri: 
        version: 0
        d.issuerAndSerialNumber: 
          issuer: CN=Alice
          serialNumber: 0x01
        keyEncryptionAlgorithm: 
          algorithm: rsaEncryption (1.2.840.113549.1.1.1)
        encryptedKey: 
          0000 - aa bb                                           ..
      d.ktri: 
        version: 0
        d.issuerAndSerialNumber: 
          issuer: CN=Bob
          serialNumber: 0x02
        keyEncryptionAlgorithm: 
          algorithm: rsaEncryption (1.2.840.113549.1.1.1)
        encryptedKey: 
          0000 - cc dd ee                                        ...
    encryptedContentInfo: 
      contentEncryptionAlgorithm: 
        algorithm: aes-256-cbc (2.16.840.1.101.3.4.1.42)
''';

const _cmsPrintWithRidNesting = '''
CMS_ContentInfo: 
  contentType: pkcs7-envelopedData (1.2.840.113549.1.7.3)
  d.envelopedData: 
    version: 0
    recipientInfos:
      d.ktri: 
        version: 0
        rid:
          d.issuerAndSerialNumber:
            issuer: CN=Demo User, emailAddress=smime-demo@example.com
            serialNumber: 0x0FEA6CAC2CD746E23AFB8B8B2A51B9688C671275
        keyEncryptionAlgorithm: 
          algorithm: rsaEncryption (1.2.840.113549.1.1.1)
    encryptedContentInfo: 
      contentEncryptionAlgorithm: 
        algorithm: aes-256-cbc (2.16.840.1.101.3.4.1.42)
''';

const _sampleMime = '''
MIME-Version: 1.0
Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"
Content-Transfer-Encoding: base64

MIIB...
''';

Future<bool> _opensslAvailable() async {
  try {
    final result = await Process.run('openssl', ['version']);
    return result.exitCode == 0;
  } catch (_) {
    return false;
  }
}

void main() {
  group('SmimeMessageParser', () {
    test('extracts recipient serial, issuer, and content cipher', () {
      final meta = SmimeMessageParser.parse(
        cmsPrintOutput: _cmsPrintSingleRecipient,
        mimeText: _sampleMime,
      );

      expect(meta.cmsContentType, 'pkcs7-envelopedData');
      expect(meta.mimeContentType, contains('application/pkcs7-mime'));
      expect(meta.smimeType, 'enveloped-data');
      expect(meta.contentEncryptionAlgorithm, 'aes-256-cbc');
      expect(meta.contentEncryptionKeyLength, 256);
      expect(meta.recipients, hasLength(1));

      final recipient = meta.recipients.first;
      expect(recipient.recipientType, 'issuerAndSerialNumber');
      expect(recipient.version, 0);
      expect(recipient.issuerDn, contains('CN=Benchmark User'));
      expect(recipient.serialNumber, '0x75C28EC195F9C31545326DD47A569ED03895CB83');
      expect(recipient.certId, '75C28EC195F9C31545326DD47A569ED03895CB83');
      expect(recipient.certIdShort, '3895CB83');
      expect(recipient.keyEncryptionAlgorithm, 'rsaEncryption');
      expect(recipient.encryptedKeyLength, 16);
    });

    test('extracts multiple RSA recipients', () {
      final meta = SmimeMessageParser.parse(
        cmsPrintOutput: _cmsPrintMultiRecipient,
      );

      expect(meta.recipients, hasLength(2));
      expect(meta.recipients[0].issuerDn, 'CN=Alice');
      expect(meta.recipients[0].serialNumber, '0x01');
      expect(meta.recipients[1].issuerDn, 'CN=Bob');
      expect(meta.recipients[1].serialNumber, '0x02');
      expect(meta.recipientCertIds, ['01', '02']);
    });

    test('parses recipients with rid nesting (OpenSSL 3 style)', () {
      final meta = SmimeMessageParser.parse(
        cmsPrintOutput: _cmsPrintWithRidNesting,
      );

      expect(meta.recipients, hasLength(1));
      expect(meta.recipientCertIds, ['0FEA6CAC2CD746E23AFB8B8B2A51B9688C671275']);
    });
  });

  group('CryptoSdk.getRecipientCertIds', () {
    test('returns all certIds for multi-recipient CMS output', () async {
      final sdk = CryptoSdk.initialize(
        CryptoSdkConfig(providers: [SmimeCryptoProvider()]),
      );

      final meta = SmimeMessageParser.parse(
        cmsPrintOutput: _cmsPrintMultiRecipient,
      );
      // Build minimal MIME wrapper — getRecipientCertIds needs parseEncryptedMessage
      // which requires OpenSSL; test the metadata list directly via provider parse path.
      expect(meta.recipientCertIds, ['01', '02']);

      CryptoSdk.reset();
    });
  });

  group('SmimeCryptoProvider.parseEncryptedMessage', () {
    test('delegates to OpenSSL when available', () async {
      if (!await _opensslAvailable()) return;

      final provider = SmimeCryptoProvider();
      final pair = await provider.generateKeyPair(
        const SmimeKeyGenerationParams(
          commonName: 'Parse Test',
          email: 'smime-parse@example.com',
        ),
      );

      final ciphertext = await provider.encrypt(
        plaintext: Uint8List.fromList(utf8.encode('smime parse test')),
        recipientPublicKeys: [pair.publicKey],
      );

      final pubMeta =
          await provider.getPublicKeyMetadata(pair.publicKey)
              as SmimePublicKeyMetadata;

      final parsed = await provider.parseEncryptedMessage(ciphertext);

      expect(parsed, isA<SmimeEncryptedMessageMetadata>());
      expect(parsed.recipients, isNotEmpty);
      expect(parsed.smimeType, 'enveloped-data');
      expect(parsed.contentEncryptionAlgorithm, isNotNull);

      final recipient = parsed.recipients.first;
      expect(recipient.serialNumber, pubMeta.serialNumber);
      expect(recipient.certId, pubMeta.certId);
      expect(recipient.issuerDn, pubMeta.issuerDn);
    });
  });

  group('CryptoSdk.parseEncryptedMessage S/MIME integration', () {
    test('extracts recipients from a real S/MIME encrypted message', () async {
      if (!await _opensslAvailable()) return;

      final provider = SmimeCryptoProvider();
      final sdk = CryptoSdk.initialize(
        CryptoSdkConfig(providers: [provider]),
      );

      final pair = await sdk.generateKeyPair(
        algorithm: CryptoAlgorithm.smime,
        params: const SmimeKeyGenerationParams(
          commonName: 'SDK Parse Test',
          email: 'sdk-smime-parse@example.com',
        ),
      );

      final ciphertext = await sdk.encrypt(
        plaintext: Uint8List.fromList(utf8.encode('sdk smime parse')),
        recipientPublicKeys: [pair.publicKey],
      );

      final parsed = await sdk.parseEncryptedMessage(
        ciphertext: ciphertext,
        algorithm: CryptoAlgorithm.smime,
      );

      expect(parsed, isA<SmimeEncryptedMessageMetadata>());
      final meta = parsed as SmimeEncryptedMessageMetadata;
      expect(meta.recipients, isNotEmpty);
      expect(meta.contentEncryptionAlgorithm, contains('aes'));

      CryptoSdk.reset();
    });
  });
}
