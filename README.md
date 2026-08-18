# secmail_crypto_sdk

Pure Dart crypto: OpenPGP **parsing** and SDK core. Pubkey protocol lives in the SComm adapters, not here.

- **OpenPGP encrypt/sign:** add [`secmail_crypto_flutter`](packages/secmail_crypto_flutter) (`SecmailCryptoFlutter.initialize()`).
- **HTTP / pubkey protocol:** Office `@scomm/pubkey` (JS) and secMail0 `packages/scomm_pubkey` (Dart). Vault format: [CKVF](https://github.com/Cryptographic-Key-Vault-Format/sdk-dart).

See [ARCHITECTURE.md](ARCHITECTURE.md).

```bash
dart pub get
dart test
```

## Features

- OpenPGP encrypt, decrypt, sign, verify (EdDSA / Curve25519) via `secmail_crypto_flutter`
- Persistent OpenPGP worker-isolate pool (no per-call spawn overhead)
- SDK-managed key-pair storage backed by `flutter_secure_storage`
- Structured logging via a callback
- Configurable execution strategy (inline or Dart isolate)

## Quick start

```dart
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final sdk = CryptoSdk.initialize(
    CryptoSdkConfig(
      // Flutter apps: use SecmailCryptoFlutter.initialize() from secmail_crypto_flutter.
      storageProvider: InMemoryStorageProvider(),
      providers: [],
      onLog: (level, msg, [err]) => debugPrint('[$level] $msg ${err ?? ''}'),
    ),
  );

  // Generate an OpenPGP key pair
  final pair = await sdk.generateKeyPair(
    algorithm: CryptoAlgorithm.openPgp,
    params: PgpKeyGenerationParams(
      name: 'Alice',
      email: 'alice@example.com',
      passphrase: 'supersecret',
    ),
  );

  // Persist the key pair
  await sdk.storeKeyPair(storageKey: 'alice_pgp', keyPair: pair);

  // Encrypt a message
  final plaintext = utf8.encode('Hello, world!');
  final ciphertext = await sdk.encrypt(
    plaintext: Uint8List.fromList(plaintext),
    recipientPublicKeys: [pair.publicKey],
    // Optional: inferred from recipientPublicKeys.first.algorithm.
    algorithm: CryptoAlgorithm.openPgp,
  );

  // Decrypt
  final decrypted = await sdk.decrypt(
    ciphertext: ciphertext,
    privateKey: pair.privateKey,
    // Optional: inferred from privateKey.algorithm.
    algorithm: CryptoAlgorithm.openPgp,
    passphrase: 'supersecret',
  );
}
```

## Logging

```dart
CryptoSdkConfig(
  ...
  onLog: (CryptoLogLevel level, String msg, [Object? err]) {
    if (level.index >= CryptoLogLevel.warning.index) {
      Sentry.captureMessage('[$level] $msg', hint: err?.toString());
    }
  },
)
```

## Custom storage backend

```dart
class MySecureStorage implements ISecureStorageProvider {
  @override Future<void> write(...) async { ... }
  @override Future<String?> read(...) async { ... }
  @override Future<bool> containsKey(...) async { ... }
  @override Future<void> delete(...) async { ... }
  @override Future<void> deleteAll() async { ... }
}
```

## Architecture

```
secmail_crypto_sdk.dart  (barrel — public API)
└── src/
    ├── core/
    │   ├── contracts/   ICryptoProvider, ISecureStorageProvider,
    │   │                IExecutionStrategy
    │   ├── models/      CryptoKey, CryptoKeyPair, CryptoAlgorithm, ...
    │   ├── exceptions/  CryptoException (sealed) + subclasses
    │   ├── registry/    ProviderRegistry
    │   └── logging/     CryptoLogger, CryptoLogLevel, CryptoLogCallback
    ├── execution/       DirectExecutionStrategy, IsolateExecutionStrategy
    ├── storage/         InMemoryStorageProvider
    ├── providers/
    │   └── openpgp/     OpenPGP message parser (crypto ops in Flutter addon)
    └── sdk/             CryptoSdk, CryptoSdkConfig
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `openpgp` | OpenPGP FFI / platform channels |
| [`fl-start/flutter_secure_storage`](https://github.com/fl-start/flutter_secure_storage) | Secure key-value storage (via `secmail_crypto_flutter`) |
| `cryptography` | Available for future providers |
| `crypto` | Available for future providers |

## Requirements

- Dart SDK `>=3.10.0 <4.0.0`
