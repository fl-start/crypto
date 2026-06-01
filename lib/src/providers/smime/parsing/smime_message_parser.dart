import 'dart:typed_data';

import '../../../core/models/encrypted_message_metadata.dart';
import 'cms_der_recipient_parser.dart';

/// Parses `openssl cms -cmsout -print` output and MIME headers from
/// S/MIME encrypted messages.
class SmimeMessageParser {
  const SmimeMessageParser._();

  /// Parses OpenSSL CMS print output and optional MIME header text.
  ///
  /// When [pkcs7Der] is supplied and text parsing yields no recipient IDs,
  /// recipient identifiers are extracted from the PKCS#7 DER structure
  /// (required on some OpenSSL builds that omit `rid` from `-print` output).
  static SmimeEncryptedMessageMetadata parse({
    required String cmsPrintOutput,
    String? mimeText,
    Uint8List? pkcs7Der,
  }) {
    final mimeHeaders = mimeText == null
        ? const _MimeHeaders()
        : _parseMime(mimeText);
    final cmsContentType = _firstMatch(
      cmsPrintOutput,
      RegExp(r'contentType:\s*(\S+)', caseSensitive: false),
    );

    final contentEncryptionAlgorithm = _firstMatch(
      cmsPrintOutput,
      RegExp(
        r'contentEncryptionAlgorithm:\s*\n\s*algorithm:\s*(\S+)',
        multiLine: true,
        caseSensitive: false,
      ),
    );

    var recipients = _parseRecipients(cmsPrintOutput);

    if (_recipientsMissingIds(recipients) && pkcs7Der != null) {
      final derRecipients = CmsDerRecipientParser.parseRecipientIds(pkcs7Der);
      if (derRecipients.isNotEmpty) {
        recipients = _mergeRecipients(recipients, derRecipients);
      }
    }

    return SmimeEncryptedMessageMetadata(
      cmsContentType: cmsContentType,
      mimeContentType: mimeHeaders.contentType,
      smimeType: mimeHeaders.smimeType,
      recipients: recipients,
      contentEncryptionAlgorithm: contentEncryptionAlgorithm,
      contentEncryptionKeyLength: _keyLengthFromAlgorithm(
        contentEncryptionAlgorithm,
      ),
    );
  }

  static List<SmimeRecipientInfoEntry> _parseRecipients(String text) {
    var entries = <SmimeRecipientInfoEntry>[];

    entries.addAll(_splitSections(text, 'd.ktri:').map(_parseKtriBlock));
    entries.addAll(_splitSections(text, 'd.kari:').expand(_parseKariBlock));

    if (entries.isEmpty) {
      for (final block in _splitSections(text, 'recipientInfo:')) {
        if (block.contains('d.ktri:') || block.contains('d.kari:')) continue;
        entries.add(_parseGenericRecipientBlock(block));
      }
    }

    if (entries.isEmpty || _recipientsMissingIds(entries)) {
      entries = _mergeRecipients(
        entries,
        _parseRecipientsFromIdentifierBlocks(text),
      );
    }

    return entries;
  }

  static bool _recipientsMissingIds(List<SmimeRecipientInfoEntry> entries) =>
      entries.isEmpty || entries.every((e) => e.certId == null);

  /// Merges [textEntries] with [other], preferring identifier fields from
  /// [other] when [textEntries] lack cert IDs.
  static List<SmimeRecipientInfoEntry> _mergeRecipients(
    List<SmimeRecipientInfoEntry> textEntries,
    List<SmimeRecipientInfoEntry> other,
  ) {
    if (textEntries.isEmpty) return other;
    if (_recipientsMissingIds(textEntries)) {
      return other
          .map(
            (der) => textEntries.isNotEmpty
                ? SmimeRecipientInfoEntry(
                    version: der.version,
                    recipientType: der.recipientType,
                    issuerDn: der.issuerDn ?? textEntries.first.issuerDn,
                    serialNumber:
                        der.serialNumber ?? textEntries.first.serialNumber,
                    subjectKeyIdentifier:
                        der.subjectKeyIdentifier ??
                        textEntries.first.subjectKeyIdentifier,
                    keyEncryptionAlgorithm:
                        der.keyEncryptionAlgorithm ??
                        textEntries.first.keyEncryptionAlgorithm,
                    encryptedKeyLength:
                        textEntries.first.encryptedKeyLength ??
                        der.encryptedKeyLength,
                  )
                : der,
          )
          .toList();
    }
    return textEntries;
  }

  /// Fallback scan for issuer/serial and SKI blocks anywhere in CMS output.
  ///
  /// Handles OpenSSL variants that nest identifiers under `rid:` or omit the
  /// `d.` prefix (common with OpenSSL 3.x on Windows).
  static List<SmimeRecipientInfoEntry> _parseRecipientsFromIdentifierBlocks(
    String text,
  ) {
    final entries = <SmimeRecipientInfoEntry>[];
    final seen = <String>{};

    final issuerBlocks = RegExp(
      r'(?:d\.)?issuerAndSerialNumber:\s*\n((?:[ \t].*\n)+)',
      multiLine: true,
    ).allMatches(text);

    for (final match in issuerBlocks) {
      final section = match.group(1)!;
      final issuer = RegExp(
        r'^\s*issuer:\s*(.+)$',
        multiLine: true,
        caseSensitive: false,
      ).firstMatch(section)?.group(1)?.trim();
      final serial = _parseSerialNumber(section);

      if (serial == null || serial.isEmpty) continue;
      final dedupeKey = 'serial:$serial';
      if (!seen.add(dedupeKey)) continue;

      entries.add(
        SmimeRecipientInfoEntry(
          version: 0,
          recipientType: 'issuerAndSerialNumber',
          issuerDn: issuer,
          serialNumber: serial,
          keyEncryptionAlgorithm: _parseKeyEncryptionAlgorithm(
            text.substring(match.start),
          ),
        ),
      );
    }

    final skiBlocks = RegExp(
      r'(?:d\.)?subjectKeyIdentifier:\s*\n((?:[ \t].*\n)+)',
      multiLine: true,
    ).allMatches(text);

    for (final match in skiBlocks) {
      final ski = _parseHexDumpOrInline(match.group(1)!);
      if (ski == null || ski.isEmpty) continue;
      final dedupeKey = 'ski:$ski';
      if (!seen.add(dedupeKey)) continue;

      entries.add(
        SmimeRecipientInfoEntry(
          version: 0,
          recipientType: 'subjectKeyIdentifier',
          subjectKeyIdentifier: ski,
          keyEncryptionAlgorithm: _parseKeyEncryptionAlgorithm(
            text.substring(match.start),
          ),
        ),
      );
    }

    return entries;
  }

  static String? _parseHexDumpOrInline(String section) {
    final inline = RegExp(
      r'^\s*([0-9A-Fa-f:]+)\s*$',
      multiLine: true,
    ).firstMatch(section)?.group(1)?.trim();
    if (inline != null && inline.contains(':')) {
      return inline.replaceAll(':', '').toUpperCase();
    }

    var hex = StringBuffer();
    for (final line in section.split('\n')) {
      if (!RegExp(r'^\s+\d{4}\s+-').hasMatch(line)) continue;
      final dashIdx = line.indexOf('-');
      var hexPart = line.substring(dashIdx + 1);
      final asciiCol = hexPart.indexOf('  ');
      if (asciiCol >= 0) hexPart = hexPart.substring(0, asciiCol);
      for (final byte in RegExp(r'[0-9a-fA-F]{2}').allMatches(hexPart)) {
        hex.write(byte.group(0));
      }
    }
    final result = hex.toString().toUpperCase();
    return result.isEmpty ? null : result;
  }

  /// Splits [text] into sections that each start with [marker].
  static List<String> _splitSections(String text, String marker) {
    final indices = <int>[];
    var searchFrom = 0;
    while (true) {
      final index = text.indexOf(marker, searchFrom);
      if (index < 0) break;
      indices.add(index);
      searchFrom = index + marker.length;
    }
    if (indices.isEmpty) return const [];

    return [
      for (int i = 0; i < indices.length; i++)
        text.substring(
          indices[i],
          i + 1 < indices.length ? indices[i + 1] : text.length,
        ),
    ];
  }

  static SmimeRecipientInfoEntry _parseKtriBlock(String block) {
    final version =
        int.tryParse(
          RegExp(r'version:\s*(\d+)').firstMatch(block)?.group(1) ?? '0',
        ) ??
        0;

    final issuerSerial = _parseIssuerAndSerial(block);
    final ski = _parseSubjectKeyIdentifier(block);
    final keyEncAlgo = _parseKeyEncryptionAlgorithm(block);
    final encryptedKeyLength = _parseEncryptedKeyLength(block);

    final recipientType = issuerSerial != null
        ? 'issuerAndSerialNumber'
        : (ski != null ? 'subjectKeyIdentifier' : 'keyTransport');

    return SmimeRecipientInfoEntry(
      version: version,
      recipientType: recipientType,
      issuerDn: issuerSerial?.$1,
      serialNumber: issuerSerial?.$2,
      subjectKeyIdentifier: ski,
      keyEncryptionAlgorithm: keyEncAlgo,
      encryptedKeyLength: encryptedKeyLength,
    );
  }

  static List<SmimeRecipientInfoEntry> _parseKariBlock(String block) {
    final version =
        int.tryParse(
          RegExp(r'version:\s*(\d+)').firstMatch(block)?.group(1) ?? '0',
        ) ??
        0;
    final keyEncAlgo = _parseKeyEncryptionAlgorithm(block);

    final subBlocks = RegExp(
      r'recipientEncryptedKeys:\s*\n((?:[ \t].*\n)+)',
      multiLine: true,
    ).allMatches(block);

    if (subBlocks.isEmpty) {
      return [
        SmimeRecipientInfoEntry(
          version: version,
          recipientType: 'keyAgreement',
          keyEncryptionAlgorithm: keyEncAlgo,
        ),
      ];
    }

    return subBlocks.map((match) {
      final sub = match.group(1)!;
      final issuerSerial = _parseIssuerAndSerial(sub);
      final ski = _parseSubjectKeyIdentifier(sub);
      final encryptedKeyLength = _parseEncryptedKeyLength(sub);

      return SmimeRecipientInfoEntry(
        version: version,
        recipientType: 'keyAgreement',
        issuerDn: issuerSerial?.$1,
        serialNumber: issuerSerial?.$2,
        subjectKeyIdentifier: ski,
        keyEncryptionAlgorithm: keyEncAlgo,
        encryptedKeyLength: encryptedKeyLength,
      );
    }).toList();
  }

  static SmimeRecipientInfoEntry _parseGenericRecipientBlock(String block) {
    final version =
        int.tryParse(
          RegExp(r'version:\s*(\d+)').firstMatch(block)?.group(1) ?? '0',
        ) ??
        0;
    final issuerSerial = _parseIssuerAndSerial(block);
    final ski = _parseSubjectKeyIdentifier(block);

    return SmimeRecipientInfoEntry(
      version: version,
      recipientType: issuerSerial != null
          ? 'issuerAndSerialNumber'
          : (ski != null ? 'subjectKeyIdentifier' : 'unknown'),
      issuerDn: issuerSerial?.$1,
      serialNumber: issuerSerial?.$2,
      subjectKeyIdentifier: ski,
      keyEncryptionAlgorithm: _parseKeyEncryptionAlgorithm(block),
      encryptedKeyLength: _parseEncryptedKeyLength(block),
    );
  }

  static (String issuer, String serial)? _parseIssuerAndSerial(String block) {
    final section = RegExp(
      r'(?:d\.)?issuerAndSerialNumber:\s*\n((?:[ \t].*\n)+)',
      multiLine: true,
    ).firstMatch(block)?.group(1);
    if (section == null) return null;

    final issuer = RegExp(
      r'^\s*issuer:\s*(.+)$',
      multiLine: true,
      caseSensitive: false,
    ).firstMatch(section)?.group(1)?.trim();
    final serial = RegExp(
      r'^\s*serialNumber:\s*(.+)$',
      multiLine: true,
      caseSensitive: false,
    ).firstMatch(section)?.group(1)?.trim();

    if (issuer == null && serial == null) return null;
    return (issuer ?? '', serial ?? '');
  }

  static String? _parseSubjectKeyIdentifier(String block) {
    final sectionMatch = RegExp(
      r'(?:d\.)?subjectKeyIdentifier:\s*\n((?:[ \t].*\n)+)',
      multiLine: true,
      caseSensitive: false,
    ).firstMatch(block);
    if (sectionMatch != null) {
      return _parseHexDumpOrInline(sectionMatch.group(1)!);
    }

    // Some OpenSSL versions print SKI inline after the label.
    final inline = RegExp(
      r'(?:d\.)?subjectKeyIdentifier:\s*([0-9A-Fa-f:]+)',
      caseSensitive: false,
    ).firstMatch(block)?.group(1)?.trim();
    return inline?.replaceAll(':', '').toUpperCase();
  }

  static String? _parseSerialNumber(String section) {
    final inline = RegExp(
      r'^\s*serialNumber:\s*(.+)$',
      multiLine: true,
      caseSensitive: false,
    ).firstMatch(section)?.group(1)?.trim();
    if (inline != null && inline.isNotEmpty && !inline.startsWith('INTEGER')) {
      return inline;
    }

    final integerLine = RegExp(
      r'^\s*INTEGER\s*:?\s*([0-9A-Fa-fx:]+)\s*$',
      multiLine: true,
      caseSensitive: false,
    ).firstMatch(section)?.group(1)?.trim();
    return integerLine ?? inline;
  }

  static String? _parseKeyEncryptionAlgorithm(String block) {
    return RegExp(
      r'keyEncryptionAlgorithm:\s*\n\s*algorithm:\s*(\S+)',
      multiLine: true,
      caseSensitive: false,
    ).firstMatch(block)?.group(1)?.trim();
  }

  static int? _parseEncryptedKeyLength(String block) {
    final start = RegExp(
      r'encryptedKey:\s*\n',
      multiLine: true,
    ).firstMatch(block)?.end;
    if (start == null) return null;

    var byteCount = 0;
    for (final line in block.substring(start).split('\n')) {
      if (!RegExp(r'^\s+\d{4}\s+-').hasMatch(line)) break;
      final dashIdx = line.indexOf('-');
      var hexPart = line.substring(dashIdx + 1);
      final asciiCol = hexPart.indexOf('  ');
      if (asciiCol >= 0) hexPart = hexPart.substring(0, asciiCol);
      byteCount += RegExp(r'[0-9a-fA-F]{2}').allMatches(hexPart).length;
    }

    return byteCount == 0 ? null : byteCount;
  }

  static int? _keyLengthFromAlgorithm(String? algorithm) {
    if (algorithm == null) return null;
    final lower = algorithm.toLowerCase();
    if (lower.contains('128')) return 128;
    if (lower.contains('192')) return 192;
    if (lower.contains('256')) return 256;
    if (lower.contains('3des') || lower.contains('des-ede3')) return 168;
    return null;
  }

  static String? _firstMatch(String text, RegExp pattern) {
    return pattern.firstMatch(text)?.group(1)?.trim();
  }
}

class _MimeHeaders {
  final String? contentType;
  final String? smimeType;

  const _MimeHeaders({this.contentType, this.smimeType});
}

_MimeHeaders _parseMime(String mimeText) {
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

  return _MimeHeaders(contentType: contentType, smimeType: smimeType);
}
