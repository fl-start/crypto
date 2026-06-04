/// Base class for algorithm-specific key-generation parameters.
///
/// OpenPGP params: [PgpKeyGenerationParams] in `package:secmail_crypto_flutter`.
/// S/MIME params: [SmimeKeyGenerationParams] below.
abstract class KeyGenerationParams {
  const KeyGenerationParams();
}

/// Parameters for generating an S/MIME (RSA 2048 / X.509) key pair.
class SmimeKeyGenerationParams extends KeyGenerationParams {
  final String commonName;
  final String email;

  const SmimeKeyGenerationParams({
    required this.commonName,
    required this.email,
  });
}
