import 'algorithm_names.dart';

/// Static mirror of pubkey server [STATIC_CATALOG] (see scomm-ai/pubkey db/algorithms.js).
abstract final class PubkeyAlgorithmCatalog {
  static const openPgpDecryptChallenge = {
    PubkeyAlgorithmNames.openPgpCv25519,
    PubkeyAlgorithmNames.openPgpCv448,
  };

  static const smimeDecryptChallenge = {
    'smime-rsa-pkcs1',
    'smime-rsa-oaep-sha1',
    'smime-rsa-oaep-sha256',
    'smime-rsa-oaep-sha384',
    'smime-rsa-oaep-sha512',
  };

  /// Server accepts self-signature upload proof for these catalog rows today.
  static const selfSignatureUpload = {
    PubkeyAlgorithmNames.openPgpEd25519,
    PubkeyAlgorithmNames.openPgpEd448,
    'openpgp-rsa2048',
    'openpgp-rsa3072',
    'openpgp-rsa4096',
    'openpgp-dsa2048',
    'openpgp-ecdsa-p256',
    'openpgp-ecdsa-p384',
    'openpgp-ecdsa-p521',
    PubkeyAlgorithmNames.smimeRsaSha256,
    // PQC signing rows verify via OpenPGP wrapper on the server.
    'pqc-mldsa-44',
    'pqc-mldsa-65',
    'pqc-mldsa-87',
    'pqc-slhdsa-128f',
    'pqc-slhdsa-128s',
    'pqc-slhdsa-192f',
    'pqc-slhdsa-192s',
    'pqc-slhdsa-256f',
    'pqc-slhdsa-256s',
  };

  static bool supportsDecryptChallenge(String catalogName) =>
      openPgpDecryptChallenge.contains(catalogName) ||
      smimeDecryptChallenge.contains(catalogName);

  static bool requiresDecryptProof(String catalogName) {
    if (supportsDecryptChallenge(catalogName)) return true;
    if (catalogName.startsWith('smime-') &&
        smimeDecryptChallenge.contains(catalogName)) {
      return true;
    }
    // Encrypt / KEM rows without verify on the server.
    if (catalogName.startsWith('openpgp-') &&
        (catalogName.contains('cv') ||
            catalogName == 'openpgp-elgamal')) {
      return true;
    }
    if (catalogName.startsWith('smime-') &&
        !catalogName.contains('sha') &&
        !catalogName.startsWith('smime-ecdsa') &&
        !catalogName.startsWith('smime-ed')) {
      return true;
    }
    if (catalogName.startsWith('pqc-') &&
        !catalogName.contains('mldsa') &&
        !catalogName.contains('slhdsa')) {
      return true;
    }
    return false;
  }

  static bool supportsSelfSignatureUpload(String catalogName) =>
      selfSignatureUpload.contains(catalogName);

  /// `sigAlgorithm` field for signed HTTP requests (`openpgp` or `smime`).
  static String sigFamilyFor(String catalogName) {
    if (catalogName.startsWith('smime-')) return PubkeySigFamily.smime;
    return PubkeySigFamily.openPgp;
  }

  /// Wire `key_type` for [EncryptedPrivateKeyPayload.toMap].
  static String blobKeyTypeFor(String catalogName) {
    if (catalogName.startsWith('smime-')) return 'smime';
    return 'openpgp';
  }
}
