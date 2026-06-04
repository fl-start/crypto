import 'dart:convert';
import 'dart:typed_data';

/// Base64url without padding (pubkey server auth headers and signatures).
String encodeBase64Url(Uint8List bytes) {
  return base64Url.encode(bytes).replaceAll('=', '');
}

/// Decodes base64url with or without padding.
Uint8List decodeBase64Url(String encoded) {
  final padding = (4 - encoded.length % 4) % 4;
  return base64Url.decode(encoded + ('=' * padding));
}

/// UTF-8 JSON object as base64url (e.g. `X-Auth-Payload`).
String encodeJsonBase64Url(Map<String, Object?> json) {
  return encodeBase64Url(Uint8List.fromList(utf8.encode(jsonEncode(json))));
}
