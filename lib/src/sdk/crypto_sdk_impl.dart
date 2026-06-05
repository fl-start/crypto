import 'dart:convert';
import 'dart:typed_data';

import '../core/contracts/i_crypto_provider.dart';
import '../core/contracts/i_execution_strategy.dart';
import '../core/contracts/i_key_inspection_provider.dart';
import '../core/contracts/i_message_inspection_provider.dart';
import '../core/models/encrypted_message_metadata.dart';
import '../core/contracts/i_storage_provider.dart';
import '../core/exceptions/crypto_exceptions.dart';
import '../core/logging/crypto_logger.dart';
import '../core/models/crypto_algorithm.dart';
import '../core/models/crypto_key.dart';
import '../core/models/key_generation_params.dart';
import '../core/models/key_metadata.dart';
import '../core/models/key_type.dart';
import '../core/models/signature_verification_result.dart';
import '../core/registry/provider_registry.dart';
import '../providers/smime/smime_crypto_provider.dart';
import '../storage/in_memory_storage_provider.dart';
import 'crypto_sdk_config.dart';

/// The single entry point for all SDK cryptographic operations.
///
/// Call [CryptoSdk.initialize] once at application startup with a
/// [CryptoSdkConfig]. Afterwards use [CryptoSdk.instance] to access the
/// singleton, or keep the returned instance for dependency-injection scenarios.
///
/// The SDK exposes a minimal, stable API surface:
///   - provider registration / unregistration
///   - key generation, import, and export
///   - encrypt / decrypt / sign / verify
///   - SDK-managed secure storage for key pairs
///
/// All algorithm-specific logic lives inside provider adapters
/// ([OpenPgpCryptoProvider], [SmimeCryptoProvider]). The SDK core is
/// intentionally unaware of any concrete algorithm (Dependency Inversion).
class CryptoSdk {
  static CryptoSdk? _instance;

  final ProviderRegistry _registry;
  final ISecureStorageProvider _storage;
  final IExecutionStrategy _executionStrategy;
  final CryptoLogger _logger;

  CryptoSdk._({
    required ProviderRegistry registry,
    required ISecureStorageProvider storage,
    required IExecutionStrategy executionStrategy,
    required CryptoLogger logger,
  }) : _registry = registry,
       _storage = storage,
       _executionStrategy = executionStrategy,
       _logger = logger;

  // ── Initialization ─────────────────────────────────────────────────────────

  /// Initialises the SDK with [config], registers all listed providers, and
  /// stores the singleton for [CryptoSdk.instance].
  ///
  /// Safe to call multiple times; each call replaces the previous singleton.
  static CryptoSdk initialize([CryptoSdkConfig? config]) {
    config ??= const CryptoSdkConfig();
    final logger = CryptoLogger(config.onLog);
    final registry = ProviderRegistry();
    final storage = config.storageProvider ?? InMemoryStorageProvider();

    final startupProviders = config.providers.isNotEmpty
        ? config.providers
        : (config.autoRegisterBuiltInProviders
              ? _defaultProviders(config: config, logger: logger)
              : const <ICryptoProvider>[]);

    for (final provider in startupProviders) {
      registry.register(provider);
      logger.info('Registered provider: ${provider.algorithm.name}');
    }

    _instance = CryptoSdk._(
      registry: registry,
      storage: storage,
      executionStrategy: config.executionStrategy,
      logger: logger,
    );

    logger.info(
      'CryptoSdk initialized with '
      '${startupProviders.length} provider(s)',
    );
    return _instance!;
  }

  static List<ICryptoProvider> _defaultProviders({
    required CryptoSdkConfig config,
    required CryptoLogger logger,
  }) {
    return [
      SmimeCryptoProvider(logger: logger),
    ];
  }

  /// The singleton instance.
  ///
  /// Throws [SdkNotInitializedException] if [initialize] has not been called.
  static CryptoSdk get instance =>
      _instance ?? (throw const SdkNotInitializedException());

  /// Resets the singleton. Intended for testing only.
  static void reset() => _instance = null;

  // ── Provider management ────────────────────────────────────────────────────

  /// Registers [provider], replacing any existing provider for the same
  /// algorithm. Useful for runtime provider swaps.
  void registerProvider(ICryptoProvider provider) {
    _registry.register(provider);
    _logger.info('Provider registered: ${provider.algorithm.name}');
  }

  /// Removes the provider for [algorithm].
  ///
  /// Subsequent operations for that algorithm will throw
  /// [ProviderNotRegisteredException].
  void unregisterProvider(CryptoAlgorithm algorithm) {
    _registry.unregister(algorithm);
    _logger.info('Provider unregistered: ${algorithm.name}');
  }

  /// Returns true if a provider is registered for [algorithm].
  bool hasProvider(CryptoAlgorithm algorithm) => _registry.has(algorithm);

  /// All algorithms with a registered provider.
  List<CryptoAlgorithm> get registeredAlgorithms =>
      _registry.registeredAlgorithms;

  // ── Crypto operations ──────────────────────────────────────────────────────

  /// Encrypts [plaintext] for [recipientPublicKeys].
  ///
  /// If [algorithm] is omitted, the SDK infers it from the first recipient
  /// key.
  Future<Uint8List> encrypt({
    required Uint8List plaintext,
    required List<CryptoKey> recipientPublicKeys,
    CryptoAlgorithm? algorithm,
  }) {
    final resolvedAlgorithm = _resolveAlgorithm(
      explicit: algorithm,
      fallback: recipientPublicKeys.isNotEmpty
          ? recipientPublicKeys.first.algorithm
          : null,
    );
    return _executionStrategy.execute(
      () => _registry
          .require(resolvedAlgorithm)
          .encrypt(
            plaintext: plaintext,
            recipientPublicKeys: recipientPublicKeys,
          ),
      dataSizeHint: plaintext.length,
    );
  }

  /// Decrypts [ciphertext] with [privateKey].
  ///
  /// If [algorithm] is omitted, the SDK infers it from [privateKey].
  ///
  /// Supply [passphrase] for algorithms that require it (e.g. OpenPGP).
  Future<Uint8List> decrypt({
    required Uint8List ciphertext,
    required CryptoKey privateKey,
    CryptoAlgorithm? algorithm,
    String? passphrase,
  }) {
    final resolvedAlgorithm = _resolveAlgorithm(
      explicit: algorithm,
      fallback: privateKey.algorithm,
    );
    return _executionStrategy.execute(
      () => _registry
          .require(resolvedAlgorithm)
          .decrypt(
            ciphertext: ciphertext,
            privateKey: privateKey,
            passphrase: passphrase,
          ),
      dataSizeHint: ciphertext.length,
    );
  }

  /// Signs [data] with [signingKey] and returns detached signature bytes.
  ///
  /// If [algorithm] is omitted, the SDK infers it from [signingKey].
  Future<Uint8List> sign({
    required Uint8List data,
    required CryptoKey signingKey,
    CryptoAlgorithm? algorithm,
    String? passphrase,
  }) {
    final resolvedAlgorithm = _resolveAlgorithm(
      explicit: algorithm,
      fallback: signingKey.algorithm,
    );
    return _executionStrategy.execute(
      () => _registry
          .require(resolvedAlgorithm)
          .sign(data: data, signingKey: signingKey, passphrase: passphrase),
      dataSizeHint: data.length,
    );
  }

  /// Verifies [signature] over [data] using [publicKey].
  ///
  /// If [algorithm] is omitted, the SDK infers it from [publicKey].
  Future<SignatureVerificationResult> verify({
    required Uint8List data,
    required Uint8List signature,
    required CryptoKey publicKey,
    CryptoAlgorithm? algorithm,
  }) {
    final resolvedAlgorithm = _resolveAlgorithm(
      explicit: algorithm,
      fallback: publicKey.algorithm,
    );
    return _executionStrategy.execute(
      () => _registry
          .require(resolvedAlgorithm)
          .verify(data: data, signature: signature, publicKey: publicKey),
      dataSizeHint: data.length,
    );
  }

  // ── Key lifecycle ──────────────────────────────────────────────────────────

  /// Generates a new key pair for [algorithm] with [params].
  Future<CryptoKeyPair> generateKeyPair({
    required CryptoAlgorithm algorithm,
    required KeyGenerationParams params,
  }) {
    return _registry.require(algorithm).generateKeyPair(params);
  }

  /// Wraps [keyBytes] as an algorithm-typed public [CryptoKey].
  Future<CryptoKey> importPublicKey({
    required Uint8List keyBytes,
    required CryptoAlgorithm algorithm,
  }) {
    return _registry.require(algorithm).importPublicKey(keyBytes);
  }

  /// Wraps [keyBytes] as an algorithm-typed private [CryptoKey].
  Future<CryptoKey> importPrivateKey({
    required Uint8List keyBytes,
    required CryptoAlgorithm algorithm,
  }) {
    return _registry.require(algorithm).importPrivateKey(keyBytes);
  }

  /// Returns the canonical serialised bytes for [key] (public side).
  Uint8List exportPublicKey({required CryptoKey key}) =>
      _registry.require(key.algorithm).exportPublicKey(key);

  /// Returns the canonical serialised bytes for [key] (private side).
  Uint8List exportPrivateKey({required CryptoKey key}) =>
      _registry.require(key.algorithm).exportPrivateKey(key);

  // ── Key inspection ─────────────────────────────────────────────────────────

  /// Returns structured metadata for [key] (public side).
  ///
  /// The concrete return type depends on the algorithm:
  /// - OpenPGP → [OpenPgpPublicKeyMetadata]
  /// - S/MIME  → [SmimePublicKeyMetadata]
  ///
  /// Throws [CryptoOperationException] if the registered provider for [key]'s
  /// algorithm does not implement [IKeyInspectionProvider].
  Future<KeyMetadataBase> getPublicKeyMetadata({
    required CryptoKey key,
    CryptoAlgorithm? algorithm,
  }) {
    final resolved = _resolveAlgorithm(
      explicit: algorithm,
      fallback: key.algorithm,
    );
    final provider = _registry.require(resolved);
    if (provider is! IKeyInspectionProvider) {
      throw CryptoOperationException(
        'The registered ${resolved.name} provider does not support key inspection.',
        algorithm: resolved,
      );
    }
    return (provider as IKeyInspectionProvider).getPublicKeyMetadata(key);
  }

  /// Returns structured metadata for [key] (private side).
  ///
  /// The concrete return type depends on the algorithm:
  /// - OpenPGP → [OpenPgpPrivateKeyMetadata]
  /// - S/MIME  → [SmimePrivateKeyMetadata]
  ///
  /// Throws [CryptoOperationException] if the registered provider for [key]'s
  /// algorithm does not implement [IKeyInspectionProvider].
  Future<KeyMetadataBase> getPrivateKeyMetadata({
    required CryptoKey key,
    CryptoAlgorithm? algorithm,
  }) {
    final resolved = _resolveAlgorithm(
      explicit: algorithm,
      fallback: key.algorithm,
    );
    final provider = _registry.require(resolved);
    if (provider is! IKeyInspectionProvider) {
      throw CryptoOperationException(
        'The registered ${resolved.name} provider does not support key inspection.',
        algorithm: resolved,
      );
    }
    return (provider as IKeyInspectionProvider).getPrivateKeyMetadata(key);
  }

  // ── Message inspection ─────────────────────────────────────────────────────

  /// Parses [ciphertext] and returns structured metadata without decrypting.
  ///
  /// For OpenPGP this includes all PKESK packets (recipient [keyId]s,
  /// public-key algorithms, etc.). For S/MIME this includes all CMS recipient
  /// info records (issuer/serial, SKI, key encryption algorithm, etc.).
  ///
  /// The concrete return type depends on the algorithm:
  /// - OpenPGP → [OpenPgpEncryptedMessageMetadata]
  /// - S/MIME  → [SmimeEncryptedMessageMetadata]
  ///
  /// Throws [CryptoOperationException] if the registered provider for
  /// [algorithm] does not implement [IMessageInspectionProvider].
  Future<EncryptedMessageMetadataBase> parseEncryptedMessage({
    required Uint8List ciphertext,
    required CryptoAlgorithm algorithm,
  }) {
    final provider = _registry.require(algorithm);
    if (provider is! IMessageInspectionProvider) {
      throw CryptoOperationException(
        'The registered ${algorithm.name} provider does not support '
        'encrypted message inspection.',
        algorithm: algorithm,
      );
    }
    return _executionStrategy.execute(
      () => (provider as IMessageInspectionProvider).parseEncryptedMessage(
        ciphertext,
      ),
      dataSizeHint: ciphertext.length,
    );
  }

  /// Returns all recipient key IDs from an OpenPGP encrypted message.
  ///
  /// Multi-recipient messages include one PKESK per recipient, so this always
  /// returns a [List] (empty when none found, one element for single-recipient
  /// messages, multiple for multi-recipient).
  Future<List<String>> getRecipientKeyIds({
    required Uint8List ciphertext,
  }) async {
    final parsed = await parseEncryptedMessage(
      ciphertext: ciphertext,
      algorithm: CryptoAlgorithm.openPgp,
    );
    return switch (parsed) {
      OpenPgpEncryptedMessageMetadata meta => meta.recipientKeyIds,
      _ => const [],
    };
  }

  /// Returns all recipient certificate IDs from an S/MIME encrypted message.
  ///
  /// Multi-recipient messages include one CMS recipient info per certificate,
  /// so this always returns a [List] (empty when none found, one element for
  /// single-recipient messages, multiple for multi-recipient).
  Future<List<String>> getRecipientCertIds({
    required Uint8List ciphertext,
  }) async {
    final parsed = await parseEncryptedMessage(
      ciphertext: ciphertext,
      algorithm: CryptoAlgorithm.smime,
    );
    return switch (parsed) {
      SmimeEncryptedMessageMetadata meta => meta.recipientCertIds,
      _ => const [],
    };
  }

  // ── SDK-managed secure storage ─────────────────────────────────────────────

  /// Persists [keyPair] under [storageKey].
  ///
  /// Both [rawBytes] and [metadata] values are serialised to base64-encoded
  /// JSON so the pair round-trips through [loadKeyPair] without data loss.
  Future<void> storeKeyPair({
    required String storageKey,
    required CryptoKeyPair keyPair,
  }) async {
    await Future.wait([
      _storage.write(
        key: '${storageKey}_public',
        value: _serializeKey(keyPair.publicKey),
      ),
      _storage.write(
        key: '${storageKey}_private',
        value: _serializeKey(keyPair.privateKey),
      ),
    ]);
    _logger.debug('Key pair stored under "$storageKey"');
  }

  /// Loads a key pair previously stored under [storageKey].
  ///
  /// Returns null if either half of the pair is missing from storage.
  /// Throws [StorageException] if the stored data is corrupted.
  ///
  /// When [algorithm] is provided, the SDK validates that both loaded keys
  /// match it.
  Future<CryptoKeyPair?> loadKeyPair({
    required String storageKey,
    CryptoAlgorithm? algorithm,
  }) async {
    final results = await Future.wait([
      _storage.read(key: '${storageKey}_public'),
      _storage.read(key: '${storageKey}_private'),
    ]);
    final pubJson = results[0];
    final privJson = results[1];
    if (pubJson == null || privJson == null) return null;

    try {
      final publicKey = _deserializeKey(pubJson);
      final privateKey = _deserializeKey(privJson);

      if (algorithm != null &&
          (publicKey.algorithm != algorithm ||
              privateKey.algorithm != algorithm)) {
        throw StorageException(
          'Stored key pair at "$storageKey" has algorithm '
          '${publicKey.algorithm.name}/${privateKey.algorithm.name}, '
          'expected ${algorithm.name}.',
        );
      }

      _logger.debug('Key pair loaded from "$storageKey"');
      return CryptoKeyPair(publicKey: publicKey, privateKey: privateKey);
    } catch (e) {
      if (e is StorageException) rethrow;
      throw StorageException(
        'Failed to deserialise key pair at "$storageKey": $e',
      );
    }
  }

  /// Returns true if both halves of the key pair exist in storage.
  Future<bool> hasKeyPair({required String storageKey}) async {
    final results = await Future.wait([
      _storage.containsKey(key: '${storageKey}_public'),
      _storage.containsKey(key: '${storageKey}_private'),
    ]);
    return results[0] && results[1];
  }

  /// Deletes both halves of the key pair from storage.
  Future<void> deleteKeyPair({required String storageKey}) {
    _logger.debug('Deleting key pair "$storageKey"');
    return Future.wait([
      _storage.delete(key: '${storageKey}_public'),
      _storage.delete(key: '${storageKey}_private'),
    ]);
  }

  // ── Passphrase management ──────────────────────────────────────────────────

  static const String _passphraseKeyPrefix = 'passphrase_';

  /// Stores [passphrase] under [identity] (typically an email address).
  Future<void> storePassphrase(String identity, String passphrase) =>
      _storage.write(key: '$_passphraseKeyPrefix$identity', value: passphrase);

  /// Returns the passphrase stored for [identity], or null if absent.
  Future<String?> loadPassphrase(String identity) =>
      _storage.read(key: '$_passphraseKeyPrefix$identity');

  /// Returns true if a passphrase is stored for [identity].
  Future<bool> hasPassphrase(String identity) =>
      _storage.containsKey(key: '$_passphraseKeyPrefix$identity');

  /// Deletes the passphrase for [identity].
  Future<void> deletePassphrase(String identity) =>
      _storage.delete(key: '$_passphraseKeyPrefix$identity');

  /// Direct access to the underlying storage provider for consumers who need
  /// to persist additional data (e.g. certificates).
  ISecureStorageProvider get storage => _storage;

  // ── Internal serialisation ─────────────────────────────────────────────────

  static String _serializeKey(CryptoKey key) {
    final map = <String, dynamic>{
      'alg': key.algorithm.name,
      'type': key.type.name,
      'raw': base64Encode(key.rawBytes),
      'meta': {
        for (final entry in key.metadata.entries)
          entry.key: base64Encode(entry.value),
      },
    };
    return jsonEncode(map);
  }

  static CryptoKey _deserializeKey(String json) {
    final map = jsonDecode(json) as Map<String, dynamic>;
    final algorithm = CryptoAlgorithm.values.byName(map['alg'] as String);
    final type = KeyType.values.byName(map['type'] as String);
    final rawBytes = base64Decode(map['raw'] as String);
    final metaJson = (map['meta'] as Map<String, dynamic>?) ?? {};
    final metadata = metaJson.map(
      (k, v) => MapEntry(k, base64Decode(v as String)),
    );
    return CryptoKey(
      algorithm: algorithm,
      type: type,
      rawBytes: rawBytes,
      metadata: metadata.isEmpty ? null : metadata,
    );
  }

  CryptoAlgorithm _resolveAlgorithm({
    required CryptoAlgorithm? explicit,
    required CryptoAlgorithm? fallback,
  }) {
    final resolved = explicit ?? fallback;
    if (resolved != null) return resolved;

    throw const CryptoArgumentException(
      'Algorithm is required when it cannot be inferred from keys.',
    );
  }
}
