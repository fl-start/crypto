import 'dart:convert';
import 'dart:typed_data';

/// Normalises line endings, removes trailing whitespace, and rebuilds the
/// MIME message with exactly one blank line separating headers from body.
String normalizeSmimeText(String input) {
  var s = input.replaceAll('\r\n', '\n').replaceAll('\r', '\n');
  s = s.split('\n').map((l) => l.trimRight()).join('\n');

  final parts = s.split(RegExp(r'\n\s*\n+'));
  if (parts.length < 2) return input;

  final headerLines = parts.first
      .split('\n')
      .map((l) => l.trim())
      .where((l) => l.isNotEmpty)
      .toList();

  final bodyLines = parts
      .sublist(1)
      .join('\n')
      .split('\n')
      .map((l) => l.trim())
      .where((l) => l.isNotEmpty)
      .toList();

  return [
    ...headerLines,
    '',
    ...bodyLines,
    '',
  ].join('\r\n');
}

/// Ensures the text has proper S/MIME MIME headers.
String ensureSmimeText(String input) {
  final s = input.replaceAll('\r\n', '\n').replaceAll('\r', '\n').trim();

  if (s.toLowerCase().contains('content-type:')) {
    return normalizeSmimeText(s);
  }

  final b64 = s.replaceAll(RegExp(r'[^A-Za-z0-9+/=]'), '');
  final lines = <String>[];
  for (var i = 0; i < b64.length; i += 64) {
    lines.add(b64.substring(i, (i + 64).clamp(0, b64.length)));
  }

  return [
    'MIME-Version: 1.0',
    'Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="smime.p7m"',
    '',
    ...lines,
    '',
  ].join('\r\n');
}

/// Decodes the PKCS#7/CMS DER payload from an S/MIME MIME wrapper.
Uint8List? extractPkcs7DerFromSmime(Uint8List encryptedData) {
  final mimeText = utf8.decode(encryptedData, allowMalformed: true);
  final smime = ensureSmimeText(normalizeSmimeText(mimeText));
  final sections = smime.split('\r\n\r\n');
  if (sections.length < 2) return null;

  final b64 = sections.sublist(1).join().replaceAll(RegExp(r'\s'), '');
  if (b64.isEmpty) return null;

  try {
    return Uint8List.fromList(base64.decode(b64));
  } on FormatException {
    return null;
  }
}

/// Parses MIME headers from an S/MIME message.
({String? contentType, String? smimeType}) parseSmimeMimeHeaders(String mimeText) {
  final normalized = mimeText.replaceAll('\r\n', '\n').replaceAll('\r', '\n');
  final headerSection = normalized.split(RegExp(r'\n\s*\n')).first;

  String? contentType;
  String? smimeType;

  for (final line in headerSection.split('\n')) {
    final trimmed = line.trim();
    if (!trimmed.toLowerCase().startsWith('content-type:')) continue;
    contentType = trimmed.substring('content-type:'.length).trim();

    final smimeMatch = RegExp(
      r'smime-type\s*=\s*([^;\s]+)',
      caseSensitive: false,
    ).firstMatch(contentType);
    smimeType = smimeMatch?.group(1)?.replaceAll('"', '');
    break;
  }

  return (contentType: contentType, smimeType: smimeType);
}
