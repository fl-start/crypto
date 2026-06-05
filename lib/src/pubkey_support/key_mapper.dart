import '../core/models/crypto_algorithm.dart';
import '../core/models/crypto_key.dart';
import '../core/models/key_metadata.dart';
import '../sdk/crypto_sdk_impl.dart';
import 'algorithm_catalog.dart';
import 'algorithm_names.dart';

/// Maps [CryptoKey] material to pubkey server catalog names.
abstract final class PubkeyKeyMapper {
  /// Resolves the server catalog name for [publicKey].
  ///
  /// When [catalogHint] is set it is returned after validation. Otherwise
  /// metadata from [sdk.getPublicKeyMetadata] is used when available.
  static Future<String> catalogNameForPublicKey(
    CryptoSdk sdk,
    CryptoKey publicKey, {
    String? catalogHint,
  }) async {
    if (catalogHint != null && catalogHint.isNotEmpty) {
      return catalogHint;
    }

    try {
      final metadata = await sdk.getPublicKeyMetadata(key: publicKey);
      return _catalogFromMetadata(metadata);
    } on Object {
      return _fallbackFromAlgorithm(publicKey.algorithm);
    }
  }

  /// Signing key used for upload proof / HTTP auth — same catalog row as public.
  static Future<String> catalogNameForSigningKey(
    CryptoSdk sdk,
    CryptoKey signingPrivateKey, {
    String? catalogHint,
  }) async {
    if (catalogHint != null && catalogHint.isNotEmpty) {
      return catalogHint;
    }
    return _fallbackFromAlgorithm(signingPrivateKey.algorithm);
  }

  static String sigFamilyForCatalog(String catalogName) =>
      PubkeyAlgorithmCatalog.sigFamilyFor(catalogName);

  static String _catalogFromMetadata(KeyMetadataBase metadata) {
    return switch (metadata) {
      OpenPgpPublicKeyMetadata m => _openPgpCatalog(m),
      SmimePublicKeyMetadata m => _smimeCatalog(m),
      _ => _fallbackFromAlgorithm(metadata.algorithm),
    };
  }

  static String _openPgpCatalog(OpenPgpPublicKeyMetadata meta) {
    final algo = meta.algorithmName.toUpperCase();

    if (meta.canEncrypt && !meta.canSign) {
      if (algo.contains('448')) return PubkeyAlgorithmNames.openPgpCv448;
      return PubkeyAlgorithmNames.openPgpCv25519;
    }

    if (algo.contains('ED448') || algo == 'ED448') {
      return PubkeyAlgorithmNames.openPgpEd448;
    }
    if (algo.contains('ED25519') ||
        algo.contains('EDDSA') ||
        algo == 'EDDSA') {
      return PubkeyAlgorithmNames.openPgpEd25519;
    }
    if (algo.contains('RSA')) {
      return _openPgpRsaCatalog(meta);
    }
    if (algo.contains('ECDSA')) {
      if (algo.contains('P521') || algo.contains('521')) {
        return 'openpgp-ecdsa-p521';
      }
      if (algo.contains('P384') || algo.contains('384')) {
        return 'openpgp-ecdsa-p384';
      }
      return 'openpgp-ecdsa-p256';
    }
    if (algo.contains('DSA')) return 'openpgp-dsa2048';
    if (algo.contains('ELGAMAL')) return 'openpgp-elgamal';

    return PubkeyAlgorithmNames.defaultOpenPgpSigning;
  }

  static String _openPgpRsaCatalog(OpenPgpPublicKeyMetadata meta) {
    final numeric = int.tryParse(meta.keyIdNumeric);
    if (numeric != null) {
      // Heuristic only — prefer explicit catalogHint when bit length matters.
      if (numeric > 0xFFFFFFFFFFFF) return 'openpgp-rsa4096';
      if (numeric > 0xFFFFFFFF) return 'openpgp-rsa3072';
    }
    return 'openpgp-rsa2048';
  }

  static String _smimeCatalog(SmimePublicKeyMetadata meta) {
    final algo = meta.publicKeyAlgorithm.toLowerCase();
    if (algo.contains('rsa')) {
      // Server upload verification accepts RSA-SHA256 detached PKCS#1 only.
      return PubkeyAlgorithmNames.defaultSmimeUploadSigning;
    }
    if (algo.contains('ed448')) return 'smime-ed448';
    if (algo.contains('ed25519')) return 'smime-ed25519';
    if (algo.contains('ecdsa') || algo.contains('id-ecPublicKey')) {
      if (meta.keyLength >= 521) return 'smime-ecdsa-sha512';
      if (meta.keyLength >= 384) return 'smime-ecdsa-sha384';
      return 'smime-ecdsa-sha256';
    }
    return PubkeyAlgorithmNames.defaultSmimeUploadSigning;
  }

  static String _fallbackFromAlgorithm(CryptoAlgorithm algorithm) {
    return switch (algorithm) {
      CryptoAlgorithm.smime => PubkeyAlgorithmNames.defaultSmimeUploadSigning,
      CryptoAlgorithm.openPgp => PubkeyAlgorithmNames.defaultOpenPgpSigning,
    };
  }
}
