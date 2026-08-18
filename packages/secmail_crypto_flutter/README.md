# secmail_crypto_flutter

Flutter addon for [secmail_crypto_sdk](../..): OpenPGP (`openpgp`) and secure storage.

## Secure storage

Uses the **fl-start** fork (not pub.dev):

[https://github.com/fl-start/flutter_secure_storage](https://github.com/fl-start/flutter_secure_storage)

- Local monorepo: **path** dependencies in [`pubspec.yaml`](pubspec.yaml) (`../../../flutter_secure_storage/...`).
- CI without a sibling clone: switch to `git` with `ref: v10.0.1-fl.1` (see fork [README_FL_START.md](https://github.com/fl-start/flutter_secure_storage/blob/develop/README_FL_START.md)).

Default storage namespace: **`secmail.crypto`** on iOS, macOS, Windows, and Linux.

```dart
import 'package:secmail_crypto_flutter/secmail_crypto_flutter.dart';

final sdk = SecmailCryptoFlutter.initialize();
```

### Desktop prerequisites

| Platform | Requirement |
|----------|-------------|
| **macOS** | Keychain; sandbox apps need entitlements ([fork docs](https://github.com/fl-start/flutter_secure_storage/blob/develop/docs/macos_entitlements.md)) |
| **Windows** | DPAPI (same Windows user); secrets in `%AppData%` under `flutter_secure_storage_secmail.crypto.dat` |
| **Linux** | `libsecret`, DBus, GNOME Keyring or KWallet; unlock keyring on first access |

See [DESKTOP_STORAGE.md](https://github.com/fl-start/flutter_secure_storage/blob/develop/DESKTOP_STORAGE.md) for threat models and options.

### Errors

Storage failures throw [`SecureStorageException`](lib/src/storage/secure_storage_exception.dart) with short guidance (keyring unlock, DPAPI, Keychain).
