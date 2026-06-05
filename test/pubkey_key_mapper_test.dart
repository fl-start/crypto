import 'dart:typed_data';

import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';
import 'package:test/test.dart';

void main() {
  group('PubkeyAlgorithmCatalog', () {
    test('cv25519 requires decrypt proof', () {
      expect(
        PubkeyAlgorithmCatalog.requiresDecryptProof(
          PubkeyAlgorithmNames.openPgpCv25519,
        ),
        isTrue,
      );
    });

    test('ed25519 supports self-signature upload', () {
      expect(
        PubkeyAlgorithmCatalog.supportsSelfSignatureUpload(
          PubkeyAlgorithmNames.openPgpEd25519,
        ),
        isTrue,
      );
    });

    test('sigFamilyFor smime vs openpgp', () {
      expect(
        PubkeyAlgorithmCatalog.sigFamilyFor('smime-rsa-sha256'),
        PubkeySigFamily.smime,
      );
      expect(
        PubkeyAlgorithmCatalog.sigFamilyFor('openpgp-ed25519'),
        PubkeySigFamily.openPgp,
      );
    });
  });

  group('PubkeyKeyMapper', () {
    test('catalogHint overrides inference', () async {
      final name = await PubkeyKeyMapper.catalogNameForPublicKey(
        CryptoSdk.initialize(),
        CryptoKey(
          algorithm: CryptoAlgorithm.openPgp,
          type: KeyType.publicKey,
          rawBytes: Uint8List(0),
        ),
        catalogHint: 'openpgp-cv25519',
      );
      expect(name, 'openpgp-cv25519');
    });

    test('fallback openpgp default when metadata unavailable', () async {
      final name = await PubkeyKeyMapper.catalogNameForPublicKey(
        CryptoSdk.initialize(),
        CryptoKey(
          algorithm: CryptoAlgorithm.openPgp,
          type: KeyType.publicKey,
          rawBytes: Uint8List(0),
        ),
      );
      expect(name, PubkeyAlgorithmNames.defaultOpenPgpSigning);
    });
  });
}
