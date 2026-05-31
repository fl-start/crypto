import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

// ── In-memory storage provider for tests ──────────────────────────────────

class _InMemoryStorageProvider implements ISecureStorageProvider {
  final Map<String, String> _store = {};

  @override
  Future<void> write({required String key, required String value}) async {
    _store[key] = value;
  }

  @override
  Future<String?> read({required String key}) async => _store[key];

  @override
  Future<bool> containsKey({required String key}) async =>
      _store.containsKey(key);

  @override
  Future<void> delete({required String key}) async => _store.remove(key);

  @override
  Future<void> deleteAll() async => _store.clear();

  @override
  Future<List<String>> readAllKeys() async => _store.keys.toList();
}

// ── Stub providers for unit testing ───────────────────────────────────────

class _StubCryptoProvider implements ICryptoProvider {
  final CryptoAlgorithm _algorithm;
  _StubCryptoProvider(this._algorithm);

  @override
  CryptoAlgorithm get algorithm => _algorithm;

  @override
  Future<Uint8List> encrypt({
    required Uint8List plaintext,
    required List<CryptoKey> recipientPublicKeys,
  }) async => Uint8List.fromList([...plaintext, 0xEE]); // append sentinel

  @override
  Future<Uint8List> decrypt({
    required Uint8List ciphertext,
    required CryptoKey privateKey,
    String? passphrase,
  }) async => ciphertext.sublist(0, ciphertext.length - 1); // strip sentinel

  @override
  Future<Uint8List> sign({
    required Uint8List data,
    required CryptoKey signingKey,
    String? passphrase,
  }) async => Uint8List.fromList([0x53, 0x49, 0x47]); // 'SIG'

  @override
  Future<SignatureVerificationResult> verify({
    required Uint8List data,
    required Uint8List signature,
    required CryptoKey publicKey,
  }) async => const SignatureVerificationResult.valid();

  @override
  Future<CryptoKeyPair> generateKeyPair(KeyGenerationParams params) async {
    return CryptoKeyPair(
      publicKey: CryptoKey(
        algorithm: _algorithm,
        type: KeyType.publicKey,
        rawBytes: Uint8List.fromList(utf8.encode('stub-public-key')),
      ),
      privateKey: CryptoKey(
        algorithm: _algorithm,
        type: KeyType.privateKey,
        rawBytes: Uint8List.fromList(utf8.encode('stub-private-key')),
      ),
    );
  }

  @override
  Future<CryptoKey> importPublicKey(Uint8List keyBytes) async => CryptoKey(
    algorithm: _algorithm,
    type: KeyType.publicKey,
    rawBytes: keyBytes,
  );

  @override
  Future<CryptoKey> importPrivateKey(Uint8List keyBytes) async => CryptoKey(
    algorithm: _algorithm,
    type: KeyType.privateKey,
    rawBytes: keyBytes,
  );

  @override
  Uint8List exportPublicKey(CryptoKey key) => key.rawBytes;

  @override
  Uint8List exportPrivateKey(CryptoKey key) => key.rawBytes;
}

// ── Helpers ────────────────────────────────────────────────────────────────

CryptoSdk _makeSdk({
  List<ICryptoProvider> providers = const [],
  bool autoRegisterBuiltInProviders = false,
}) {
  CryptoSdk.reset();
  return CryptoSdk.initialize(
    CryptoSdkConfig(
      storageProvider: _InMemoryStorageProvider(),
      providers: providers,
      autoRegisterBuiltInProviders: autoRegisterBuiltInProviders,
    ),
  );
}

void main() {
  tearDown(CryptoSdk.reset);

  // ── Initialization ──────────────────────────────────────────────────────

  group('CryptoSdk initialization', () {
    test('initialize returns a CryptoSdk instance', () {
      final sdk = _makeSdk();
      expect(sdk, isA<CryptoSdk>());
    });

    test('instance returns the singleton after initialize', () {
      _makeSdk();
      expect(CryptoSdk.instance, isA<CryptoSdk>());
    });

    test('instance throws SdkNotInitializedException before initialize', () {
      CryptoSdk.reset();
      expect(
        () => CryptoSdk.instance,
        throwsA(isA<SdkNotInitializedException>()),
      );
    });

    test('initialize replaces previous singleton', () {
      final first = _makeSdk();
      final second = _makeSdk();
      expect(identical(first, second), isFalse);
      expect(identical(second, CryptoSdk.instance), isTrue);
    });

    test('initialize auto-registers built-in providers by default', () {
      CryptoSdk.reset();
      final sdk = CryptoSdk.initialize(
        CryptoSdkConfig(storageProvider: _InMemoryStorageProvider()),
      );

      expect(sdk.hasProvider(CryptoAlgorithm.openPgp), isTrue);
      expect(sdk.hasProvider(CryptoAlgorithm.smime), isTrue);
    });
  });

  // ── Provider registry ───────────────────────────────────────────────────

  group('Provider registry', () {
    test('hasProvider returns false when no providers registered', () {
      final sdk = _makeSdk();
      expect(sdk.hasProvider(CryptoAlgorithm.openPgp), isFalse);
    });

    test('hasProvider returns true after registerProvider', () {
      final sdk = _makeSdk();
      sdk.registerProvider(_StubCryptoProvider(CryptoAlgorithm.openPgp));
      expect(sdk.hasProvider(CryptoAlgorithm.openPgp), isTrue);
    });

    test('unregisterProvider removes a provider', () {
      final sdk = _makeSdk(
        providers: [_StubCryptoProvider(CryptoAlgorithm.openPgp)],
      );
      expect(sdk.hasProvider(CryptoAlgorithm.openPgp), isTrue);
      sdk.unregisterProvider(CryptoAlgorithm.openPgp);
      expect(sdk.hasProvider(CryptoAlgorithm.openPgp), isFalse);
    });

    test('registeredAlgorithms lists all registered providers', () {
      final sdk = _makeSdk(
        providers: [
          _StubCryptoProvider(CryptoAlgorithm.openPgp),
          _StubCryptoProvider(CryptoAlgorithm.smime),
        ],
      );
      expect(
        sdk.registeredAlgorithms,
        containsAll([CryptoAlgorithm.openPgp, CryptoAlgorithm.smime]),
      );
    });

    test(
      'encrypt throws ProviderNotRegisteredException for unknown algorithm',
      () async {
        final sdk = _makeSdk();
        expect(
          () => sdk.encrypt(
            plaintext: Uint8List(4),
            recipientPublicKeys: [],
            algorithm: CryptoAlgorithm.openPgp,
          ),
          throwsA(isA<ProviderNotRegisteredException>()),
        );
      },
    );
  });

  // ── Crypto operations via stub provider ─────────────────────────────────

  group('Crypto operations (stub provider)', () {
    late CryptoSdk sdk;
    late CryptoKey pubKey;
    late CryptoKey privKey;

    setUp(() {
      sdk = _makeSdk(providers: [_StubCryptoProvider(CryptoAlgorithm.openPgp)]);
      pubKey = CryptoKey(
        algorithm: CryptoAlgorithm.openPgp,
        type: KeyType.publicKey,
        rawBytes: Uint8List.fromList(utf8.encode('pub')),
      );
      privKey = CryptoKey(
        algorithm: CryptoAlgorithm.openPgp,
        type: KeyType.privateKey,
        rawBytes: Uint8List.fromList(utf8.encode('priv')),
      );
    });

    test('encrypt produces non-empty result', () async {
      final result = await sdk.encrypt(
        plaintext: Uint8List.fromList(utf8.encode('hello')),
        recipientPublicKeys: [pubKey],
      );
      expect(result, isNotEmpty);
    });

    test('encrypt / decrypt round-trip', () async {
      final plain = Uint8List.fromList(utf8.encode('hello world'));
      final cipher = await sdk.encrypt(
        plaintext: plain,
        recipientPublicKeys: [pubKey],
      );
      final decrypted = await sdk.decrypt(
        ciphertext: cipher,
        privateKey: privKey,
      );
      expect(decrypted, equals(plain));
    });

    test('sign returns non-empty bytes', () async {
      final sig = await sdk.sign(
        data: Uint8List.fromList(utf8.encode('data')),
        signingKey: privKey,
      );
      expect(sig, isNotEmpty);
    });

    test('verify returns valid result', () async {
      final result = await sdk.verify(
        data: Uint8List.fromList(utf8.encode('data')),
        signature: Uint8List.fromList([0x53, 0x49, 0x47]),
        publicKey: pubKey,
      );
      expect(result.isValid, isTrue);
    });
  });

  // ── Key lifecycle ───────────────────────────────────────────────────────

  group('Key lifecycle', () {
    late CryptoSdk sdk;

    setUp(() {
      sdk = _makeSdk(providers: [_StubCryptoProvider(CryptoAlgorithm.openPgp)]);
    });

    test('generateKeyPair returns a CryptoKeyPair', () async {
      final pair = await sdk.generateKeyPair(
        algorithm: CryptoAlgorithm.openPgp,
        params: PgpKeyGenerationParams(
          name: 'Test User',
          email: 'test@example.com',
          passphrase: 'secret',
        ),
      );
      expect(pair.publicKey.type, KeyType.publicKey);
      expect(pair.privateKey.type, KeyType.privateKey);
    });

    test('importPublicKey wraps bytes correctly', () async {
      final bytes = Uint8List.fromList(
        utf8.encode('-----BEGIN PGP PUBLIC KEY BLOCK-----'),
      );
      final key = await sdk.importPublicKey(
        keyBytes: bytes,
        algorithm: CryptoAlgorithm.openPgp,
      );
      expect(key.type, KeyType.publicKey);
      expect(key.rawBytes, equals(bytes));
    });

    test('importPrivateKey wraps bytes correctly', () async {
      final bytes = Uint8List.fromList(
        utf8.encode('-----BEGIN PGP PRIVATE KEY BLOCK-----'),
      );
      final key = await sdk.importPrivateKey(
        keyBytes: bytes,
        algorithm: CryptoAlgorithm.openPgp,
      );
      expect(key.type, KeyType.privateKey);
    });

    test('exportPublicKey returns raw bytes', () async {
      final bytes = Uint8List.fromList(utf8.encode('pub-key-data'));
      final key = await sdk.importPublicKey(
        keyBytes: bytes,
        algorithm: CryptoAlgorithm.openPgp,
      );
      expect(sdk.exportPublicKey(key: key), equals(bytes));
    });
  });

  // ── SDK-managed storage ─────────────────────────────────────────────────

  group('SDK-managed key pair storage', () {
    late CryptoSdk sdk;
    late CryptoKeyPair pair;

    setUp(() async {
      sdk = _makeSdk(providers: [_StubCryptoProvider(CryptoAlgorithm.openPgp)]);
      pair = await sdk.generateKeyPair(
        algorithm: CryptoAlgorithm.openPgp,
        params: PgpKeyGenerationParams(
          name: 'Alice',
          email: 'alice@example.com',
          passphrase: 'p@ss',
        ),
      );
    });

    test('storeKeyPair and hasKeyPair', () async {
      await sdk.storeKeyPair(storageKey: 'alice', keyPair: pair);
      expect(await sdk.hasKeyPair(storageKey: 'alice'), isTrue);
    });

    test('loadKeyPair returns null when absent', () async {
      final loaded = await sdk.loadKeyPair(storageKey: 'nobody');
      expect(loaded, isNull);
    });

    test('storeKeyPair / loadKeyPair round-trip', () async {
      await sdk.storeKeyPair(storageKey: 'alice', keyPair: pair);
      final loaded = await sdk.loadKeyPair(storageKey: 'alice');
      expect(loaded, isNotNull);
      expect(loaded!.publicKey.rawBytes, equals(pair.publicKey.rawBytes));
      expect(loaded.privateKey.rawBytes, equals(pair.privateKey.rawBytes));
    });

    test('deleteKeyPair removes both halves', () async {
      await sdk.storeKeyPair(storageKey: 'alice', keyPair: pair);
      await sdk.deleteKeyPair(storageKey: 'alice');
      expect(await sdk.hasKeyPair(storageKey: 'alice'), isFalse);
    });

    test('storeKeyPair preserves metadata', () async {
      final certBytes = Uint8List.fromList(utf8.encode('CERT'));
      final keyWithMeta = CryptoKey(
        algorithm: CryptoAlgorithm.smime,
        type: KeyType.privateKey,
        rawBytes: Uint8List.fromList(utf8.encode('KEY')),
        metadata: {'certificate': certBytes},
      );
      final pairWithMeta = CryptoKeyPair(
        publicKey: CryptoKey(
          algorithm: CryptoAlgorithm.smime,
          type: KeyType.publicKey,
          rawBytes: Uint8List.fromList(utf8.encode('PUB')),
        ),
        privateKey: keyWithMeta,
      );

      await sdk.storeKeyPair(storageKey: 'bob', keyPair: pairWithMeta);
      final loaded = await sdk.loadKeyPair(
        storageKey: 'bob',
        algorithm: CryptoAlgorithm.smime,
      );
      expect(loaded, isNotNull);
      expect(loaded!.privateKey.metadata['certificate'], equals(certBytes));
    });

    test('loadKeyPair throws when expected algorithm does not match', () async {
      await sdk.storeKeyPair(storageKey: 'alice', keyPair: pair);

      expect(
        () => sdk.loadKeyPair(
          storageKey: 'alice',
          algorithm: CryptoAlgorithm.smime,
        ),
        throwsA(isA<StorageException>()),
      );
    });
  });

  // ── Exceptions ──────────────────────────────────────────────────────────

  group('Exception hierarchy', () {
    test('SdkNotInitializedException toString contains class name', () {
      const ex = SdkNotInitializedException();
      expect(ex.toString(), contains('SdkNotInitializedException'));
    });

    test('ProviderNotRegisteredException carries the algorithm', () {
      final ex = ProviderNotRegisteredException(CryptoAlgorithm.smime);
      expect(ex.algorithm, CryptoAlgorithm.smime);
      expect(ex.toString(), contains('smime'));
    });

    test('CryptoOperationException carries cause', () {
      final cause = Exception('underlying error');
      final ex = CryptoOperationException('op failed', cause: cause);
      expect(ex.cause, same(cause));
    });

    test('StorageException message is accessible', () {
      const ex = StorageException('disk full');
      expect(ex.message, 'disk full');
    });
  });

  // ── Models ──────────────────────────────────────────────────────────────

  group('SignatureVerificationResult', () {
    test('valid result has isValid = true and no failureReason', () {
      const r = SignatureVerificationResult.valid();
      expect(r.isValid, isTrue);
      expect(r.failureReason, isNull);
    });

    test('invalid result has isValid = false and a failureReason', () {
      const r = SignatureVerificationResult.invalid('sig mismatch');
      expect(r.isValid, isFalse);
      expect(r.failureReason, 'sig mismatch');
    });
  });

  group('CryptoKey', () {
    test('metadata is unmodifiable', () {
      final key = CryptoKey(
        algorithm: CryptoAlgorithm.openPgp,
        type: KeyType.publicKey,
        rawBytes: Uint8List(1),
        metadata: {'cert': Uint8List(4)},
      );
      expect(
        () => key.metadata['other'] = Uint8List(1),
        throwsA(isA<UnsupportedError>()),
      );
    });

    test('metadata defaults to empty map when not provided', () {
      final key = CryptoKey(
        algorithm: CryptoAlgorithm.openPgp,
        type: KeyType.publicKey,
        rawBytes: Uint8List(1),
      );
      expect(key.metadata, isEmpty);
    });
  });

  // ── Execution strategies ────────────────────────────────────────────────

  group('DirectExecutionStrategy', () {
    test('executes work and returns result', () async {
      const strategy = DirectExecutionStrategy();
      final result = await strategy.execute(() async => 42);
      expect(result, 42);
    });
  });

  group('IsolateExecutionStrategy', () {
    test('disabled config executes inline', () async {
      const strategy = IsolateExecutionStrategy(IsolateConfig.disabled);
      final result = await strategy.execute(() async => 'ok');
      expect(result, 'ok');
    });

    test('always config offloads to isolate', () async {
      const strategy = IsolateExecutionStrategy(IsolateConfig.always);
      final result = await strategy.execute(() async => 'isolated');
      expect(result, 'isolated');
    });
  });

  // ── Logging ─────────────────────────────────────────────────────────────

  group('CryptoLogger', () {
    test('silent logger does not throw', () {
      CryptoLogger.silent.debug('msg');
      CryptoLogger.silent.info('msg');
      CryptoLogger.silent.warning('msg', Exception('err'));
      CryptoLogger.silent.error('msg', Exception('err'));
    });

    test('callback logger receives all levels', () {
      final events = <CryptoLogLevel>[];
      final logger = CryptoLogger((level, msg, [err]) => events.add(level));
      logger.debug('d');
      logger.info('i');
      logger.warning('w');
      logger.error('e');
      expect(events, [
        CryptoLogLevel.debug,
        CryptoLogLevel.info,
        CryptoLogLevel.warning,
        CryptoLogLevel.error,
      ]);
    });

    test('CryptoSdkConfig onLog callback is invoked during initialize', () {
      final levels = <CryptoLogLevel>[];
      CryptoSdk.reset();
      CryptoSdk.initialize(
        CryptoSdkConfig(
          storageProvider: _InMemoryStorageProvider(),
          providers: [_StubCryptoProvider(CryptoAlgorithm.openPgp)],
          onLog: (level, msg, [err]) => levels.add(level),
        ),
      );
      expect(levels, isNotEmpty);
    });
  });
}
