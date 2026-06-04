import 'dart:convert';
import 'dart:io' show Platform;

import 'package:flutter/foundation.dart'
    show TargetPlatform, defaultTargetPlatform, kIsWeb, visibleForTesting;
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

import 'secure_storage_exception.dart';

/// Logical namespace for SecMail secrets (Keychain service / DPAPI file / libsecret entry).
const String secmailSecureStorageAccountName = 'secmail.crypto';

/// Reserved key storing a JSON array of user key names (Windows/Linux key listing).
const String secmailKeyIndexStorageKey = '__secmail_key_index__';

/// [ISecureStorageProvider] backed by [FlutterSecureStorage].
///
/// Uses [fl-start/flutter_secure_storage](https://github.com/fl-start/flutter_secure_storage)
/// (RSA OAEP + AES-GCM on Android by default).
///
/// On Windows and Linux, [readAllKeys] uses [secmailKeyIndexStorageKey] so the
/// implementation does not call [FlutterSecureStorage.readAll] (which decrypts
/// the full namespace blob).
class FlutterSecureStorageProvider implements ISecureStorageProvider {
  FlutterSecureStorageProvider({FlutterSecureStorage? storage})
      : _storage = storage ?? secmailDefaultFlutterSecureStorage;

  final FlutterSecureStorage _storage;

  /// Shared instance with SecMail platform namespaces.
  static final FlutterSecureStorage secmailDefaultFlutterSecureStorage =
      FlutterSecureStorage(
        aOptions: AndroidOptions(),
        iOptions: IOSOptions(accountName: secmailSecureStorageAccountName),
        mOptions: MacOsOptions(accountName: secmailSecureStorageAccountName),
        wOptions: const WindowsOptions(
          accountName: secmailSecureStorageAccountName,
        ),
        lOptions: const LinuxOptions(
          accountName: secmailSecureStorageAccountName,
        ),
      );

  static bool get _useKeyIndex {
    if (kIsWeb) return false;
    if (Platform.isWindows || Platform.isLinux) return true;
    return false;
  }

  @override
  Future<void> write({required String key, required String value}) =>
      _guard(() async {
        await _storage.write(key: key, value: value);
        if (_useKeyIndex && key != secmailKeyIndexStorageKey) {
          await _addKeyToIndex(key);
        }
      });

  @override
  Future<String?> read({required String key}) =>
      _guard(() => _storage.read(key: key));

  @override
  Future<bool> containsKey({required String key}) =>
      _guard(() => _storage.containsKey(key: key));

  @override
  Future<void> delete({required String key}) => _guard(() async {
        await _storage.delete(key: key);
        if (_useKeyIndex && key != secmailKeyIndexStorageKey) {
          await _removeKeyFromIndex(key);
        }
      });

  @override
  Future<void> deleteAll() => _guard(() async {
        await _storage.deleteAll();
        if (_useKeyIndex) {
          await _storage.delete(key: secmailKeyIndexStorageKey);
        }
      });

  @override
  Future<List<String>> readAllKeys() => _guard(() async {
        if (_useKeyIndex) {
          final raw = await _storage.read(key: secmailKeyIndexStorageKey);
          if (raw == null || raw.isEmpty) return [];
          final decoded = jsonDecode(raw);
          if (decoded is! List) {
            throw SecureStorageException(
              'Key index is corrupted; delete "$secmailKeyIndexStorageKey" or call deleteAll().',
            );
          }
          return decoded
              .whereType<String>()
              .where((k) => k != secmailKeyIndexStorageKey)
              .toList();
        }

        final all = await _storage.readAll();
        return all.keys
            .where((k) => k != secmailKeyIndexStorageKey)
            .toList();
      });

  Future<void> _addKeyToIndex(String key) async {
    final keys = await readAllKeys();
    if (keys.contains(key)) return;
    keys.add(key);
    await _storage.write(
      key: secmailKeyIndexStorageKey,
      value: jsonEncode(keys),
    );
  }

  Future<void> _removeKeyFromIndex(String key) async {
    final keys = await readAllKeys();
    if (!keys.remove(key)) return;
    if (keys.isEmpty) {
      await _storage.delete(key: secmailKeyIndexStorageKey);
    } else {
      await _storage.write(
        key: secmailKeyIndexStorageKey,
        value: jsonEncode(keys),
      );
    }
  }

  Future<T> _guard<T>(Future<T> Function() action) async {
    try {
      return await action();
    } on PlatformException catch (e) {
      throw SecureStorageException(_friendlyMessage(e), cause: e);
    }
  }

  @visibleForTesting
  static String friendlyMessageForTest(PlatformException e) =>
      _friendlyMessage(e);

  static String _friendlyMessage(PlatformException e) {
    final code = e.code;
    final message = e.message ?? '';
    final details = e.details?.toString() ?? '';
    final combined = '$code $message $details'.toLowerCase();

    if (combined.contains('libsecret')) {
      return 'Linux keyring is locked or unavailable. Unlock your keyring '
          '(GNOME Keyring / KWallet) and ensure DBus is running.';
    }
    if (combined.contains('cryptunprotectdata') ||
        combined.contains('cryptprotectdata') ||
        combined.contains('dpapi')) {
      return 'Windows could not decrypt stored secrets for the current user. '
          'Sign in with the same account or clear corrupted storage.';
    }
    if (combined.contains('security result') ||
        combined.contains('errsec') ||
        combined.contains('keychain')) {
      return 'macOS/iOS Keychain denied access. Check entitlements and unlock '
          'the device; see flutter_secure_storage macOS entitlements docs.';
    }
    if (defaultTargetPlatform == TargetPlatform.linux &&
        combined.contains('failed to unlock')) {
      return 'Could not unlock the Linux keyring. Cancelled prompts leave '
          'storage unavailable until you retry.';
    }

    return message.isNotEmpty ? message : 'Secure storage operation failed.';
  }
}
