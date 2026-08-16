import 'package:flutter_test/flutter_test.dart';
import 'package:secmail_crypto_flutter/secmail_crypto_flutter.dart';
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

void main() {
  test('FlutterSecureVaultStore round-trips ciphertext JSON', () async {
    final store = FlutterSecureVaultStore(storage: InMemoryStorageProvider());
    expect(await store.load(), isNull);
    await store.save({
      'vault_format_version': 1,
      'ciphertext': 'dGVzdA',
    });
    final loaded = await store.load();
    expect(loaded!['vault_format_version'], 1);
    expect(loaded['ciphertext'], 'dGVzdA');
    await store.clear();
    expect(await store.load(), isNull);
  });
}
