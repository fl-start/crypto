import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secmail_crypto_flutter/src/storage/flutter_secure_storage_provider.dart';
import 'package:secmail_crypto_flutter/src/storage/secure_storage_exception.dart';

void main() {
  group('SecureStorageException mapping', () {
    test('libsecret errors get Linux guidance', () {
      final message = FlutterSecureStorageProvider.friendlyMessageForTest(
        PlatformException(
          code: 'Libsecret error',
          message: 'The name org.freedesktop.secrets was not provided',
        ),
      );
      expect(message, contains('keyring'));
    });

    test('DPAPI errors get Windows guidance', () {
      final message = FlutterSecureStorageProvider.friendlyMessageForTest(
        PlatformException(
          code: 'Exception',
          message: 'Failure on CryptUnprotectData()',
        ),
      );
      expect(message, contains('Windows'));
    });

    test('Keychain errors get Apple guidance', () {
      final message = FlutterSecureStorageProvider.friendlyMessageForTest(
        PlatformException(
          code: 'Unexpected security result code',
          message: 'Code: -34018',
        ),
      );
      expect(message, contains('Keychain'));
    });
  });

  group('namespace constants', () {
    test('account name matches across platform option defaults', () {
      expect(secmailSecureStorageAccountName, 'secmail.crypto');
      expect(
        FlutterSecureStorageProvider.secmailDefaultFlutterSecureStorage,
        isNotNull,
      );
    });
  });
}
