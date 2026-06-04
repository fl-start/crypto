import 'dart:convert';

import 'package:crypto/crypto.dart';

/// SHA-256 hex digest of the exact HTTP JSON body bytes (pubkey signed requests).
String sha256HexOfUtf8Body(String jsonBody) {
  return sha256.convert(utf8.encode(jsonBody)).toString();
}

/// SHA-256 hex digest of raw request bytes.
String sha256HexOfBytes(List<int> bytes) {
  return sha256.convert(bytes).toString();
}
