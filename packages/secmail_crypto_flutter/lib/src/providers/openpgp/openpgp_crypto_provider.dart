import 'dart:isolate';
import 'dart:typed_data';

import 'package:openpgp/openpgp.dart';
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';
import 'package:secmail_crypto_sdk/src/providers/openpgp/parsing/openpgp_message_parser.dart';

import '../../pgp_key_generation_params.dart';
import 'worker/openpgp_op.dart';
import 'worker/openpgp_worker_pool.dart';

/// [ICryptoProvider] implementation for OpenPGP (EdDSA / Curve25519).
///
/// All crypto operations (encrypt, decrypt, sign, verify) are dispatched to a
/// persistent pool of worker isolates via [OpenPgpWorkerPool], avoiding the
/// 40–80 ms spawn cost of `compute()` on every call.
///
/// Key generation uses `Isolate.run()` because it is an infrequent, one-shot
/// operation that does not benefit from a persistent worker.
///
/// Key format:
///   [CryptoKey.rawBytes] = UTF-8 bytes of the ASCII-armored OpenPGP key block.
class OpenPgpCryptoProvider
    implements ICryptoProvider, IKeyInspectionProvider, IMessageInspectionProvider {
  final OpenPgpWorkerPool _pool;
  final CryptoLogger _log;

  /// Creates a provider backed by an [OpenPgpWorkerPool].
  ///
  /// [poolSize] controls how many worker isolates are maintained (1–4).
  /// [logger] receives lifecycle and error events.
  OpenPgpCryptoProvider({
    int poolSize = 1,
    CryptoLogger logger = CryptoLogger.silent,
  }) : _pool = OpenPgpWorkerPool(poolSize: poolSize, logger: logger),
       _log = logger;

  @override
  CryptoAlgorithm get algorithm => CryptoAlgorithm.openPgp;

  // ── Pool management ────────────────────────────────────────────────────────

  /// Pre-warms the worker pool. Call at startup to avoid cold-start latency on
  /// the first crypto operation. Idempotent.
  Future<void> ensureInitialized() => _pool.ensureInitialized();

  /// Shuts down all worker isolates. In-flight jobs will fail.
  Future<void> shutdown() => _pool.shutdown();

  // ── Crypto operations ──────────────────────────────────────────────────────

  @override
  Future<Uint8List> encrypt({
    required Uint8List plaintext,
    required List<CryptoKey> recipientPublicKeys,
  }) async {
    if (recipientPublicKeys.isEmpty) {
      throw const CryptoArgumentException(
        'At least one recipient public key is required for OpenPGP encryption.',
      );
    }
    _assertAlgorithm(recipientPublicKeys);

    // The openpgp package accepts concatenated armored public-key blocks for
    // multi-recipient encryption in a single pass.
    final combinedKey = recipientPublicKeys
        .map((k) => k.rawBytes)
        .reduce((acc, bytes) => Uint8List.fromList([...acc, ...bytes]));

    try {
      final result = await _pool.run(
        op: OpenPgpOp.encrypt,
        payload: {
          'data': TransferableTypedData.fromList([plaintext]),
          'recipientKey': TransferableTypedData.fromList([combinedKey]),
        },
      );
      return (result as TransferableTypedData).materialize().asUint8List();
    } catch (e) {
      _log.error('OpenPGP encrypt failed', e);
      throw CryptoOperationException(
        'OpenPGP encrypt failed: $e',
        algorithm: algorithm,
        cause: e,
      );
    }
  }

  /// Encrypts [data] (as a Dart [String]) for [recipientKey].
  ///
  /// This is a non-interface convenience method retained for backward
  /// compatibility with call sites that work with string plaintext directly.
  Future<String> encryptString({
    required String data,
    required Uint8List recipientKey,
  }) async {
    try {
      final result = await _pool.run(
        op: OpenPgpOp.encryptString,
        payload: {
          'data': data,
          'recipientKey': TransferableTypedData.fromList([recipientKey]),
        },
      );
      return result as String;
    } catch (e) {
      _log.error('OpenPGP encryptString failed', e);
      throw CryptoOperationException(
        'OpenPGP encryptString failed: $e',
        algorithm: algorithm,
        cause: e,
      );
    }
  }

  @override
  Future<Uint8List> decrypt({
    required Uint8List ciphertext,
    required CryptoKey privateKey,
    String? passphrase,
  }) async {
    _assertKeyType(privateKey, KeyType.privateKey);
    if (passphrase == null || passphrase.isEmpty) {
      throw const CryptoArgumentException(
        'Passphrase is required for OpenPGP decryption.',
      );
    }
    try {
      final result = await _pool.run(
        op: OpenPgpOp.decrypt,
        payload: {
          'encryptedData': TransferableTypedData.fromList([ciphertext]),
          'privateKey': TransferableTypedData.fromList([privateKey.rawBytes]),
          'passphrase': passphrase,
        },
      );
      return (result as TransferableTypedData).materialize().asUint8List();
    } catch (e) {
      _log.error('OpenPGP decrypt failed', e);
      throw CryptoOperationException(
        'OpenPGP decrypt failed: $e',
        algorithm: algorithm,
        cause: e,
      );
    }
  }

  @override
  Future<Uint8List> sign({
    required Uint8List data,
    required CryptoKey signingKey,
    String? passphrase,
  }) async {
    _assertKeyType(signingKey, KeyType.privateKey);
    if (passphrase == null || passphrase.isEmpty) {
      throw const CryptoArgumentException(
        'Passphrase is required for OpenPGP signing.',
      );
    }
    try {
      final result = await _pool.run(
        op: OpenPgpOp.sign,
        payload: {
          'data': TransferableTypedData.fromList([data]),
          'signingKey': TransferableTypedData.fromList([signingKey.rawBytes]),
          'passphrase': passphrase,
        },
      );
      return (result as TransferableTypedData).materialize().asUint8List();
    } catch (e) {
      _log.error('OpenPGP sign failed', e);
      throw CryptoOperationException(
        'OpenPGP sign failed: $e',
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
    try {
      final result = await _pool.run(
        op: OpenPgpOp.verify,
        payload: {
          'data': TransferableTypedData.fromList([data]),
          'signature': TransferableTypedData.fromList([signature]),
          'publicKey': TransferableTypedData.fromList([publicKey.rawBytes]),
        },
      );
      final isValid = result as bool;
      return isValid
          ? const SignatureVerificationResult.valid()
          : const SignatureVerificationResult.invalid(
              'OpenPGP signature did not match.',
            );
    } catch (e) {
      _log.error('OpenPGP verify failed', e);
      throw CryptoOperationException(
        'OpenPGP verify failed: $e',
        algorithm: algorithm,
        cause: e,
      );
    }
  }

  // ── Key lifecycle ──────────────────────────────────────────────────────────

  @override
  Future<CryptoKeyPair> generateKeyPair(KeyGenerationParams params) async {
    if (params is! PgpKeyGenerationParams) {
      throw CryptoArgumentException(
        'OpenPgpCryptoProvider requires PgpKeyGenerationParams, '
        'got ${params.runtimeType}.',
      );
    }

    final ko = params.keyOptions;
    final options = Options()
      ..name = params.name
      ..email = params.email
      ..passphrase = params.passphrase
      ..keyOptions = (KeyOptions()
        ..algorithm = ko.algorithm
        ..curve = ko.curve
        ..hash = ko.hash
        ..cipher = ko.cipher
        ..compression = ko.compression
        ..compressionLevel = ko.compressionLevel);

    _log.info('Generating OpenPGP key pair for ${params.email}');
    final keyPair = await Isolate.run(
      () async => OpenPGP.generate(options: options),
    );

    return CryptoKeyPair(
      publicKey: CryptoKey(
        algorithm: CryptoAlgorithm.openPgp,
        type: KeyType.publicKey,
        rawBytes: Uint8List.fromList(keyPair.publicKey.codeUnits),
      ),
      privateKey: CryptoKey(
        algorithm: CryptoAlgorithm.openPgp,
        type: KeyType.privateKey,
        rawBytes: Uint8List.fromList(keyPair.privateKey.codeUnits),
      ),
    );
  }

  @override
  Future<CryptoKey> importPublicKey(Uint8List keyBytes) async {
    return CryptoKey(
      algorithm: CryptoAlgorithm.openPgp,
      type: KeyType.publicKey,
      rawBytes: keyBytes,
    );
  }

  @override
  Future<CryptoKey> importPrivateKey(Uint8List keyBytes) async {
    return CryptoKey(
      algorithm: CryptoAlgorithm.openPgp,
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

  /// Returns [OpenPgpPublicKeyMetadata] for [key].
  ///
  /// Delegates to [OpenPGP.getPublicKeyMetadata] inside the worker isolate so
  /// that the native FFI / platform-channel call runs on the correct binding.
  @override
  Future<OpenPgpPublicKeyMetadata> getPublicKeyMetadata(CryptoKey key) async {
    _assertKeyType(key, KeyType.publicKey);
    try {
      final result = await _pool.run(
        op: OpenPgpOp.getPublicKeyMetadata,
        payload: {
          'publicKey': TransferableTypedData.fromList([key.rawBytes]),
        },
      );
      return OpenPgpPublicKeyMetadata.fromMap(
        Map<String, dynamic>.from(result as Map),
      );
    } catch (e) {
      _log.error('OpenPGP getPublicKeyMetadata failed', e);
      throw CryptoOperationException(
        'OpenPGP getPublicKeyMetadata failed: $e',
        algorithm: algorithm,
        cause: e,
      );
    }
  }

  /// Returns [OpenPgpPrivateKeyMetadata] for [key].
  ///
  /// Delegates to [OpenPGP.getPrivateKeyMetadata] inside the worker isolate so
  /// that the native FFI / platform-channel call runs on the correct binding.
  @override
  Future<OpenPgpPrivateKeyMetadata> getPrivateKeyMetadata(CryptoKey key) async {
    _assertKeyType(key, KeyType.privateKey);
    try {
      final result = await _pool.run(
        op: OpenPgpOp.getPrivateKeyMetadata,
        payload: {
          'privateKey': TransferableTypedData.fromList([key.rawBytes]),
        },
      );
      return OpenPgpPrivateKeyMetadata.fromMap(
        Map<String, dynamic>.from(result as Map),
      );
    } catch (e) {
      _log.error('OpenPGP getPrivateKeyMetadata failed', e);
      throw CryptoOperationException(
        'OpenPGP getPrivateKeyMetadata failed: $e',
        algorithm: algorithm,
        cause: e,
      );
    }
  }

  // ── Message inspection ─────────────────────────────────────────────────────

  /// Parses [ciphertext] and returns [OpenPgpEncryptedMessageMetadata].
  ///
  /// Extracts all PKESK packets (recipient key IDs, public-key algorithms,
  /// etc.) without decrypting the message. Runs synchronously in pure Dart —
  /// no worker isolate is needed because no native OpenPGP calls are made.
  @override
  Future<OpenPgpEncryptedMessageMetadata> parseEncryptedMessage(
    Uint8List ciphertext,
  ) async {
    try {
      return OpenPgpMessageParser.parse(ciphertext);
    } on CryptoArgumentException {
      rethrow;
    } catch (e) {
      _log.error('OpenPGP parseEncryptedMessage failed', e);
      throw CryptoOperationException(
        'OpenPGP parseEncryptedMessage failed: $e',
        algorithm: algorithm,
        cause: e,
      );
    }
  }

  // ── Passphrase validation ──────────────────────────────────────────────────

  /// Verifies that [passphrase] can unlock [armoredPrivateKey] by attempting
  /// a trial sign operation.
  ///
  /// Throws [CryptoArgumentException] if the passphrase is incorrect.
  Future<void> validatePassphrase({
    required String armoredPrivateKey,
    required String passphrase,
  }) async {
    final args = (key: armoredPrivateKey, passphrase: passphrase);
    final valid = await Isolate.run(() => _trySign(args));
    if (!valid) throw const CryptoArgumentException('Invalid passphrase.');
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  void _assertAlgorithm(List<CryptoKey> keys) {
    for (final k in keys) {
      if (k.algorithm != CryptoAlgorithm.openPgp) {
        throw CryptoArgumentException(
          'Key algorithm mismatch: expected openPgp, got ${k.algorithm.name}.',
        );
      }
    }
  }

  void _assertKeyType(CryptoKey key, KeyType expected) {
    if (key.type != expected) {
      throw CryptoArgumentException(
        'Key type mismatch: expected ${expected.name}, got ${key.type.name}.',
      );
    }
  }
}

// ── Top-level helpers (isolate-safe) ──────────────────────────────────────

typedef _TestArgs = ({String key, String passphrase});

Future<bool> _trySign(_TestArgs args) async {
  try {
    await OpenPGP.signBytes(Uint8List.fromList([0]), args.key, args.passphrase);
    return true;
  } catch (_) {
    return false;
  }
}
