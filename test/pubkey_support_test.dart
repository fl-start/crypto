import 'dart:convert';

import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';
import 'package:test/test.dart';

void main() {
  group('pubkey_support encoding', () {
    test('base64url round-trip', () {
      final bytes = utf8.encode('hello');
      final encoded = encodeBase64Url(bytes);
      expect(encoded.contains('='), isFalse);
      expect(decodeBase64Url(encoded), bytes);
    });
  });

  group('pubkey_support body_hash', () {
    test('sha256HexOfUtf8Body is stable', () {
      const body = '{"email":"a@b.com"}';
      final h1 = sha256HexOfUtf8Body(body);
      final h2 = sha256HexOfUtf8Body(body);
      expect(h1, h2);
      expect(h1.length, 64);
    });
  });
}
