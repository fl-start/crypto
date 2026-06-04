import '../core/contracts/i_storage_provider.dart';

/// Volatile [ISecureStorageProvider] for tests, CLI, and non-Flutter hosts.
class InMemoryStorageProvider implements ISecureStorageProvider {
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
  Future<void> delete({required String key}) async {
    _store.remove(key);
  }

  @override
  Future<void> deleteAll() async {
    _store.clear();
  }

  @override
  Future<List<String>> readAllKeys() async => _store.keys.toList(growable: false);
}
