import 'package:openpgp/openpgp.dart';
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

/// Cryptographic options for OpenPGP key generation.
class PgpKeyOptions {
  final Algorithm algorithm;
  final Curve curve;
  final Hash hash;
  final Cipher cipher;
  final Compression compression;
  final int compressionLevel;

  const PgpKeyOptions({
    this.algorithm = Algorithm.EDDSA,
    this.curve = Curve.CURVE25519,
    this.hash = Hash.SHA256,
    this.cipher = Cipher.AES256,
    this.compression = Compression.ZLIB,
    this.compressionLevel = 6,
  });
}

/// Parameters for generating an OpenPGP key pair.
class PgpKeyGenerationParams extends KeyGenerationParams {
  final String name;
  final String email;
  final String passphrase;
  final PgpKeyOptions keyOptions;

  const PgpKeyGenerationParams({
    required this.name,
    required this.email,
    required this.passphrase,
    this.keyOptions = const PgpKeyOptions(),
  });
}
