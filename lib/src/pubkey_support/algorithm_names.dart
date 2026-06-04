/// Server catalog names from [scomm-ai/pubkey](https://github.com/scomm-ai/pubkey).
///
/// Used by [secmail_pubkey_sdk] when uploading keys or building signed requests.
abstract final class PubkeyAlgorithmNames {
  static const openPgpEd25519 = 'openpgp-ed25519';
  static const openPgpCv25519 = 'openpgp-cv25519';
  static const smimeRsaSha256 = 'smime-rsa-sha256';

  /// Default signing algorithm for OpenPGP keys generated with [PgpKeyOptions] defaults.
  static const defaultOpenPgpSigning = openPgpEd25519;

  /// Only S/MIME catalog row accepted for upload proof on the pubkey server today.
  static const defaultSmimeUploadSigning = smimeRsaSha256;
}

/// High-level family strings in signed-request payloads (`sigAlgorithm`).
abstract final class PubkeySigFamily {
  static const openPgp = 'openpgp';
  static const smime = 'smime';
}
