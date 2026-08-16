# Architecture

This repo is **OpenPGP / S/MIME engines and secure storage**. The Pubkey
protocol (MSK, Vault HTTP, `POST /v1/mutate`, discovery) lives in
`sdk_pubkey` (`secmail_pubkey_sdk`). Do not implement enroll/mutate here.

## Packages

| Package | Path | Flutter? |
|---------|------|----------|
| **secmail_crypto_sdk** | repo root | **No** — pure Dart (`dart pub get`, `dart test`) |
| **secmail_crypto_flutter** | `packages/secmail_crypto_flutter` | **Yes** — OpenPGP (`openpgp`) + `flutter_secure_storage` + Vault ciphertext store |

## Rules for `secmail_crypto_sdk`

- No `flutter`, `openpgp`, or `http`/`dio` in this package's `pubspec.yaml`.
- S/MIME via bundled OpenSSL **libcrypto** (`SmimeLibcryptoBackend`).
- The `openssl` CLI engine is test-only quarantine (`SmimeOpensslEngine`).
- Parsers and in-memory storage stay here.
- No pubkey protocol helpers (`X-Auth-Payload`, decrypt-challenge, upload catalog).

## Flutter apps

```dart
import 'package:secmail_crypto_flutter/secmail_crypto_flutter.dart';

final sdk = SecmailCryptoFlutter.initialize();
final vaultStore = FlutterSecureVaultStore();
```

`FlutterSecureVaultStore` persists the **already encrypted** sdk_pubkey Vault
JSON under `scomm.vault.v1`. It does not hold raw private keys.

## Pubkey HTTP

All REST and MSK/Vault protocol live in **secmail_pubkey_sdk**, not here.
