import 'dart:typed_data';

import '../../core/contracts/i_certificate_signing_service.dart';
import '../../core/contracts/i_crypto_provider.dart';
import '../../core/contracts/i_key_inspection_provider.dart';
import '../../core/contracts/i_message_inspection_provider.dart';
import '../../core/models/encrypted_message_metadata.dart';
import '../../core/exceptions/crypto_exceptions.dart';
import '../../core/logging/crypto_logger.dart';
import '../../core/models/crypto_algorithm.dart';
import '../../core/models/crypto_key.dart';
import '../../core/models/key_generation_params.dart';
import '../../core/models/key_metadata.dart';
import '../../core/models/key_type.dart';
import '../../core/models/signature_verification_result.dart';
import 'backend/i_smime_backend.dart';
import 'backend/smime_libcrypto_backend.dart';
import 'backend/smime_libcrypto_cert_generator.dart';

/// [ICryptoProvider] implementation for S/MIME (RSA 2048 / X.509).
///
/// All cryptographic operations are delegated to an internal [ISmimeBackend]
/// (libcrypto via [package:openssl]). Certificate generation uses
/// [SmimeLibcryptoCertGenerator].
///
/// Key format conventions:
///   - Public key  → [CryptoKey.rawBytes] = PEM X.509 certificate bytes.
///   - Private key → [CryptoKey.rawBytes] = PEM private-key bytes.
///     [CryptoKey.metadata]['certificate'] = PEM certificate bytes (required
///     when the key is used for signing).
///
/// To enable S/MIME signature chain validation, set
/// [CryptoKey.metadata]['caCertificate'] = CA PEM bytes on the sender's public
/// key before calling [verify].
class SmimeCryptoProvider
    implements ICryptoProvider, IKeyInspectionProvider, IMessageInspectionProvider {
  final ISmimeBackend _engine;
  final SmimeLibcryptoCertGenerator _certGen;
  final CryptoLogger _log;

  /// Creates an S/MIME provider backed by bundled OpenSSL libcrypto.
  ///
  /// [signingService] is an optional CA-signing integration for certificate
  /// generation. When null, self-signed certificates are always used.
  /// [logger] receives operational events.
  /// [backend] is test-only; production uses [SmimeLibcryptoBackend].
  SmimeCryptoProvider({
    ICertificateSigningService? signingService,
    CryptoLogger logger = CryptoLogger.silent,
    ISmimeBackend? backend,
  }) : _engine = backend ?? SmimeLibcryptoBackend(logger: logger),
       _certGen = SmimeLibcryptoCertGenerator(
         signingService: signingService,
         logger: logger,
       ),
       _log = logger;

  @override
  CryptoAlgorithm get algorithm => CryptoAlgorithm.smime;

  // ── Crypto operations ──────────────────────────────────────────────────────

  @override
  Future<Uint8List> encrypt({
    required Uint8List plaintext,
    required List<CryptoKey> recipientPublicKeys,
  }) async {
    if (recipientPublicKeys.isEmpty) {
      throw const CryptoArgumentException(
        'At least one recipient certificate is required for S/MIME encryption.',
      );
    }
    final certificates = recipientPublicKeys.map((k) => k.rawBytes).toList();
    try {
      return await _engine.encrypt(data: plaintext, certificates: certificates);
    } catch (e) {
      _log.error('S/MIME encrypt failed', e);
      throw CryptoOperationException(
        'S/MIME encrypt failed: $e',
        algorithm: algorithm,
        cause: e,
      );
    }
  }

  @override
  Future<Uint8List> decrypt({
    required Uint8List ciphertext,
    required CryptoKey privateKey,
    String? passphrase, // unused — S/MIME private keys are unprotected
  }) async {
    _assertKeyType(privateKey, KeyType.privateKey);
    try {
      return await _engine.decrypt(
        encryptedData: ciphertext,
        privateKey: privateKey.rawBytes,
      );
    } catch (e) {
      _log.error('S/MIME decrypt failed', e);
      throw CryptoOperationException(
        'S/MIME decrypt failed: $e',
        algorithm: algorithm,
        cause: e,
      );
    }
  }

  @override
  Future<Uint8List> sign({
    required Uint8List data,
    required CryptoKey signingKey,
    String? passphrase, // unused for S/MIME
  }) async {
    _assertKeyType(signingKey, KeyType.privateKey);
    final cert = signingKey.metadata['certificate'];
    if (cert == null) {
      throw const CryptoArgumentException(
        "S/MIME signing requires the signer's certificate. "
        "Supply it as CryptoKey.metadata['certificate'] (PEM bytes).",
      );
    }
    try {
      return await _engine.sign(
        data: data,
        privateKey: signingKey.rawBytes,
        signerCertificate: cert,
      );
    } catch (e) {
      _log.error('S/MIME sign failed', e);
      throw CryptoOperationException(
        'S/MIME sign failed: $e',
        algorithm: algorithm,
        cause: e,
      );
    }
  }

  @override
  Future<SignatureVerificationResult> verify({
    required Uint8List data,
    required Uint8List signature,
    required CryptoKey publicKey,
  }) async {
    _assertKeyType(publicKey, KeyType.publicKey);
    final caCert = publicKey.metadata['caCertificate'];
    try {
      final isValid = await _engine.verify(
        data: data,
        signature: signature,
        senderCertificate: publicKey.rawBytes,
        caCertificate: caCert,
      );
      return isValid
          ? const SignatureVerificationResult.valid()
          : const SignatureVerificationResult.invalid(
              'S/MIME certificate verification failed.',
            );
    } catch (e) {
      _log.error('S/MIME verify failed', e);
      throw CryptoOperationException(
        'S/MIME verify failed: $e',
        algorithm: algorithm,
        cause: e,
      );
    }
  }

  // ── Key lifecycle ──────────────────────────────────────────────────────────

  @override
  Future<CryptoKeyPair> generateKeyPair(KeyGenerationParams params) async {
    if (params is! SmimeKeyGenerationParams) {
      throw CryptoArgumentException(
        'SmimeCryptoProvider requires SmimeKeyGenerationParams, '
        'got ${params.runtimeType}.',
      );
    }

    _log.info('Generating S/MIME key pair for ${params.email}');
    final bundle = await _certGen.generate(
      commonName: params.commonName,
      email: params.email,
    );

    final certBytes = Uint8List.fromList(bundle.certificatePem.codeUnits);

    return CryptoKeyPair(
      publicKey: CryptoKey(
        algorithm: CryptoAlgorithm.smime,
        type: KeyType.publicKey,
        rawBytes: certBytes,
      ),
      privateKey: CryptoKey(
        algorithm: CryptoAlgorithm.smime,
        type: KeyType.privateKey,
        rawBytes: bundle.privateKey,
        metadata: {'certificate': certBytes},
      ),
    );
  }

  @override
  Future<CryptoKey> importPublicKey(Uint8List keyBytes) async {
    return CryptoKey(
      algorithm: CryptoAlgorithm.smime,
      type: KeyType.publicKey,
      rawBytes: keyBytes,
    );
  }

  /// Imports a private key.
  ///
  /// To enable signing, also supply the matching [certificate] PEM bytes.
  Future<CryptoKey> importPrivateKeyWithCert(
    Uint8List keyBytes, {
    Uint8List? certificate,
  }) async {
    return CryptoKey(
      algorithm: CryptoAlgorithm.smime,
      type: KeyType.privateKey,
      rawBytes: keyBytes,
      metadata: certificate != null ? {'certificate': certificate} : null,
    );
  }

  @override
  Future<CryptoKey> importPrivateKey(Uint8List keyBytes) async {
    return CryptoKey(
      algorithm: CryptoAlgorithm.smime,
      type: KeyType.privateKey,
      rawBytes: keyBytes,
    );
  }

  @override
  Uint8List exportPublicKey(CryptoKey key) {
    _assertKeyType(key, KeyType.publicKey);
    return key.rawBytes;
  }

  @override
  Uint8List exportPrivateKey(CryptoKey key) {
    _assertKeyType(key, KeyType.privateKey);
    return key.rawBytes;
  }

  // ── Key inspection ─────────────────────────────────────────────────────────

  /// Returns [SmimePublicKeyMetadata] for [key] by parsing the PEM X.509
  /// certificate via `openssl x509 -text`.
  @override
  Future<SmimePublicKeyMetadata> getPublicKeyMetadata(CryptoKey key) async {
    _assertKeyType(key, KeyType.publicKey);
    try {
      return await _engine.parseCertificate(key.rawBytes);
    } catch (e) {
      _log.error('S/MIME getPublicKeyMetadata failed', e);
      throw CryptoOperationException(
        'S/MIME getPublicKeyMetadata failed: $e',
        algorithm: algorithm,
        cause: e,
      );
    }
  }

  /// Returns [SmimePrivateKeyMetadata] for [key].
  ///
  /// If `key.metadata['certificate']` is present, the bundled certificate is
  /// also parsed and attached as [SmimePrivateKeyMetadata.associatedCertificate].
  @override
  Future<SmimePrivateKeyMetadata> getPrivateKeyMetadata(CryptoKey key) async {
    _assertKeyType(key, KeyType.privateKey);
    try {
      return await _engine.parsePrivateKey(
        key.rawBytes,
        certificate: key.metadata['certificate'],
      );
    } catch (e) {
      _log.error('S/MIME getPrivateKeyMetadata failed', e);
      throw CryptoOperationException(
        'S/MIME getPrivateKeyMetadata failed: $e',
        algorithm: algorithm,
        cause: e,
      );
    }
  }

  // ── Message inspection ─────────────────────────────────────────────────────

  /// Parses [ciphertext] and returns [SmimeEncryptedMessageMetadata].
  ///
  /// Extracts all CMS recipient info records (issuer/serial, SKI, key
  /// encryption algorithm, etc.) without decrypting the message.
  @override
  Future<SmimeEncryptedMessageMetadata> parseEncryptedMessage(
    Uint8List ciphertext,
  ) async {
    try {
      return await _engine.parseEncryptedMessage(ciphertext);
    } on CryptoArgumentException {
      rethrow;
    } catch (e) {
      _log.error('S/MIME parseEncryptedMessage failed', e);
      throw CryptoOperationException(
        'S/MIME parseEncryptedMessage failed: $e',
        algorithm: algorithm,
        cause: e,
      );
    }
  }

  // ── Passphrase validation ──────────────────────────────────────────────────

  /// No-op for S/MIME — private keys are stored unencrypted in this
  /// implementation. Provided for API symmetry with [OpenPgpCryptoProvider].
  Future<void> validatePassphrase({
    required String armoredPrivateKey,
    required String passphrase,
  }) async {
    // S/MIME does not use passphrases in this implementation.
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  void _assertKeyType(CryptoKey key, KeyType expected) {
    if (key.type != expected) {
      throw CryptoArgumentException(
        'Key type mismatch: expected ${expected.name}, got ${key.type.name}.',
      );
    }
  }
}
