# Architecture

## Packages

| Package | Path | Flutter? |
|---------|------|----------|
| **secmail_crypto_sdk** | repo root | **No** — pure Dart (`dart pub get`, `dart test`) |
| **secmail_crypto_flutter** | `packages/secmail_crypto_flutter` | **Yes** — OpenPGP (`openpgp`) + [`fl-start/flutter_secure_storage`](https://github.com/fl-start/flutter_secure_storage) |
| **secmail_pubkey_sdk** | `../../scomm-ai/sdk_pubkey` | Uses dio; depends on both above for mobile |

## Rules for `secmail_crypto_sdk`

- No `flutter`, `openpgp`, or `http`/`dio` in this package's `pubspec.yaml`.
- S/MIME (OpenSSL CLI), parsers, pubkey helpers, in-memory storage.

## Flutter apps

```dart
import 'package:secmail_crypto_flutter/secmail_crypto_flutter.dart';

final sdk = SecmailCryptoFlutter.initialize();
// or: CryptoSdk.initialize(SecmailCryptoFlutter.config(CryptoSdkConfig(...)));
```

## Pubkey HTTP

All REST lives in **secmail_pubkey_sdk**, not here.
