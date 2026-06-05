# secmail_crypto_sdk

Pure Dart crypto: S/MIME, OpenPGP **parsing**, pubkey signing helpers.

- **OpenPGP encrypt/sign:** add [`secmail_crypto_flutter`](packages/secmail_crypto_flutter) (`SecmailCryptoFlutter.initialize()`).
- **HTTP / pubkey server:** [`scomm-ai/sdk_pubkey`](../../scomm-ai/sdk_pubkey).

See [ARCHITECTURE.md](ARCHITECTURE.md).

```bash
dart pub get
dart run openssl:setup_prebuilts   # once: fetch libcrypto prebuilts for S/MIME FFI
dart test
```

## Features

- OpenPGP encrypt, decrypt, sign, verify (EdDSA / Curve25519)
- S/MIME encrypt, decrypt, sign, verify (RSA 2048 / X.509)
- Persistent OpenPGP worker-isolate pool (no per-call spawn overhead)
- SDK-managed key-pair storage backed by `flutter_secure_storage`
- Optional CA-signing integration for S/MIME certificate generation
- Structured logging via a callback
- Configurable execution strategy (inline or Dart isolate)

## Quick start

```dart
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final sdk = CryptoSdk.initialize(
    CryptoSdkConfig(
      // Optional: when omitted, FlutterSecureStorageProvider is used.
      // storageProvider: FlutterSecureStorageProvider(),
      // Optional: when omitted, built-in OpenPGP and S/MIME providers
      // are auto-registered.
      // providers: [OpenPgpCryptoProvider(poolSize: 2), SmimeCryptoProvider()],
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

## S/MIME example

```dart
final sdk = CryptoSdk.initialize(
  CryptoSdkConfig(
    storageProvider: FlutterSecureStorageProvider(),
    providers: [SmimeCryptoProvider()],
  ),
);

final pair = await sdk.generateKeyPair(
  algorithm: CryptoAlgorithm.smime,
  params: SmimeKeyGenerationParams(
    commonName: 'Bob Smith',
    email: 'bob@example.com',
  ),
);
```

## CA-signed S/MIME certificates

Implement `ICertificateSigningService` and pass it to `SmimeCryptoProvider`:

```dart
class MyCaService implements ICertificateSigningService {
  @override
  Future<String?> signCsr({
    required String csrPem,
    required String email,
    required String commonName,
  }) async {
    final resp = await myApi.post('/sign-csr', {'csr': csrPem, 'email': email});
    return resp['certificate'] as String?;
  }
}

SmimeCryptoProvider(signingService: MyCaService())
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
    │   │                IExecutionStrategy, ICertificateSigningService
    │   ├── models/      CryptoKey, CryptoKeyPair, CryptoAlgorithm, ...
    │   ├── exceptions/  CryptoException (sealed) + subclasses
    │   ├── registry/    ProviderRegistry
    │   └── logging/     CryptoLogger, CryptoLogLevel, CryptoLogCallback
    ├── execution/       DirectExecutionStrategy, IsolateExecutionStrategy
    ├── storage/         FlutterSecureStorageProvider
    ├── providers/
    │   ├── openpgp/     OpenPgpCryptoProvider + worker pool
    │   └── smime/       SmimeCryptoProvider + OpenSSL engine + cert generator
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

- Dart SDK `>=3.9.0 <4.0.0`
- Flutter `>=3.35.0`
- `openssl` CLI available on PATH for S/MIME operations
