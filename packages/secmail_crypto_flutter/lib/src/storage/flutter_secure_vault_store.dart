import 'dart:convert';

import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

import 'flutter_secure_storage_provider.dart';
import 'secure_storage_exception.dart';

/// OS-protected persistence for the portable SComm Vault ciphertext.
///
/// Stores one JSON record under [storageKey]. The value must already be the
/// passphrase-wrapped Vault blob from `secmail_pubkey_sdk` — never raw
/// `{email}-{provider}-{id}-private` material.
class FlutterSecureVaultStore {
  FlutterSecureVaultStore({
    ISecureStorageProvider? storage,
    this.storageKey = defaultStorageKey,
  }) : _storage = storage ?? FlutterSecureStorageProvider();

  static const defaultStorageKey = 'scomm.vault.v1';

  final ISecureStorageProvider _storage;
  final String storageKey;

  Future<Map<String, dynamic>?> load() async {
    final raw = await _storage.read(key: storageKey);
    if (raw == null || raw.isEmpty) return null;
    final decoded = jsonDecode(raw);
    if (decoded is! Map) {
      throw SecureStorageException('Vault store blob is not a JSON object');
    }
    return Map<String, dynamic>.from(decoded);
  }

  Future<void> save(Map<String, dynamic> record) {
    return _storage.write(key: storageKey, value: jsonEncode(record));
  }

  Future<void> clear() => _storage.delete(key: storageKey);
}
