import 'dart:convert';
import 'dart:typed_data';

/// Pubkey wire encoding: **base64url without padding** everywhere.
///
/// Used for `X-Auth-Payload`, `X-Auth-Signature`, upload `signature`,
/// `challengeResponse`, `ciphertext`, and FetchToken segments on both
/// client and server.

/// Base64url without padding (pubkey auth headers and signatures).
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
