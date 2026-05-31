import 'dart:typed_data';

import '../../../core/models/encrypted_message_metadata.dart';
import '../../../core/models/key_metadata.dart';

/// Extracts recipient identifiers from CMS/PKCS#7 EnvelopedData DER bytes.
///
/// Used when `openssl cms -print` omits `rid` fields (common on Windows
/// OpenSSL builds) but the binary structure still contains issuer/serial or SKI.
class CmsDerRecipientParser {
  const CmsDerRecipientParser._();

  static const _envelopedDataOid = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03,
  ];

  /// Parses [der] and returns one entry per CMS recipient info record.
  static List<SmimeRecipientInfoEntry> parseRecipientIds(Uint8List der) {
    final enveloped = _findEnvelopedDataContent(der);
    if (enveloped == null) return const [];

    final reader = _BerReader(enveloped);
    if (!reader.hasBytes || reader.peekTag() != 0x30) return const [];

    final envelopedSeq = reader.readTlv();
    final children = _BerReader(envelopedSeq.value).readAllTlvs();

    for (final child in children) {
      if (child.tag == 0x31) {
        return _parseRecipientInfosSet(child.value);
      }
    }
    return const [];
  }

  static Uint8List? _findEnvelopedDataContent(Uint8List der) {
    final index = _indexOfSublist(der, _envelopedDataOid);
    if (index < 0) return null;

    var offset = index + _envelopedDataOid.length;
    if (offset >= der.length) return null;

    // Content is [0] EXPLICIT wrapped EnvelopedData.
    if (der[offset] == 0xA0) {
      final wrapper = _BerReader(der, start: offset).readTlv();
      return wrapper.value;
    }

    // Some blobs omit the explicit wrapper.
    if (der[offset] == 0x30) {
      return der.sublist(offset);
    }
    return null;
  }

  static List<SmimeRecipientInfoEntry> _parseRecipientInfosSet(Uint8List setBytes) {
    final entries = <SmimeRecipientInfoEntry>[];
    for (final tlv in _BerReader(setBytes).readAllTlvs()) {
      entries.addAll(_parseRecipientInfo(tlv));
    }
    return entries;
  }

  static List<SmimeRecipientInfoEntry> _parseRecipientInfo(_BerTlv tlv) {
    switch (tlv.tag) {
      case 0x30:
        return [_parseKeyTransRecipientInfo(tlv.value)];
      case 0xA1:
        return _parseKeyAgreeRecipientInfo(tlv.value);
      default:
        return const [];
    }
  }

  static SmimeRecipientInfoEntry _parseKeyTransRecipientInfo(Uint8List bytes) {
    final children = _BerReader(bytes).readAllTlvs();
    var version = 0;
    String? issuerDn;
    String? serialNumber;
    String? ski;
    String? keyEncAlgo;

    var index = 0;
    if (index < children.length && children[index].tag == 0x02) {
      version = _parseInteger(children[index].value);
      index++;
    }

    if (index < children.length) {
      final rid = children[index];
      if (rid.tag == 0x30) {
        final ridChildren = _BerReader(rid.value).readAllTlvs();
        if (ridChildren.length >= 2 && ridChildren[1].tag == 0x02) {
          issuerDn = _parseName(ridChildren[0].value);
          serialNumber = _integerToHex(ridChildren[1].value);
        }
      } else if (rid.tag == 0x80 || rid.tag == 0x04) {
        ski = _octetsToHex(rid.value);
      }
      index++;
    }

    if (index < children.length && children[index].tag == 0x30) {
      keyEncAlgo = _parseAlgorithmIdentifier(children[index].value);
    }

    final recipientType = serialNumber != null
        ? 'issuerAndSerialNumber'
        : (ski != null ? 'subjectKeyIdentifier' : 'keyTransport');

    return SmimeRecipientInfoEntry(
      version: version,
      recipientType: recipientType,
      issuerDn: issuerDn,
      serialNumber: serialNumber,
      subjectKeyIdentifier: ski,
      keyEncryptionAlgorithm: keyEncAlgo,
    );
  }

  static List<SmimeRecipientInfoEntry> _parseKeyAgreeRecipientInfo(
    Uint8List bytes,
  ) {
    final children = _BerReader(bytes).readAllTlvs();
    var version = 0;
    String? keyEncAlgo;

    var index = 0;
    if (index < children.length && children[index].tag == 0x02) {
      version = _parseInteger(children[index].value);
      index++;
    }

    // Skip originatorIdentifierOrKey and ukm if present.
    while (index < children.length &&
        children[index].tag != 0x30 &&
        children[index].tag != 0xA0) {
      index++;
    }

    if (index < children.length && children[index].tag == 0x30) {
      keyEncAlgo = _parseAlgorithmIdentifier(children[index].value);
      index++;
    }

    if (index >= children.length || children[index].tag != 0xA0) {
      return [
        SmimeRecipientInfoEntry(
          version: version,
          recipientType: 'keyAgreement',
          keyEncryptionAlgorithm: keyEncAlgo,
        ),
      ];
    }

    final entries = <SmimeRecipientInfoEntry>[];
    for (final sub in _BerReader(children[index].value).readAllTlvs()) {
      if (sub.tag != 0x30) continue;
      final subChildren = _BerReader(sub.value).readAllTlvs();
      String? issuerDn;
      String? serialNumber;
      String? ski;

      for (final part in subChildren) {
        if (part.tag == 0x30 && serialNumber == null && ski == null) {
          final ridChildren = _BerReader(part.value).readAllTlvs();
          if (ridChildren.length >= 2 && ridChildren[1].tag == 0x02) {
            issuerDn = _parseName(ridChildren[0].value);
            serialNumber = _integerToHex(ridChildren[1].value);
          }
        } else if ((part.tag == 0x80 || part.tag == 0x04) && ski == null) {
          ski = _octetsToHex(part.value);
        }
      }

      entries.add(
        SmimeRecipientInfoEntry(
          version: version,
          recipientType: 'keyAgreement',
          issuerDn: issuerDn,
          serialNumber: serialNumber,
          subjectKeyIdentifier: ski,
          keyEncryptionAlgorithm: keyEncAlgo,
        ),
      );
    }

    return entries;
  }

  static String? _parseAlgorithmIdentifier(Uint8List bytes) {
    final children = _BerReader(bytes).readAllTlvs();
    if (children.isEmpty || children.first.tag != 0x06) return null;
    return _oidToName(children.first.value);
  }

  static String? _oidToName(Uint8List oidBytes) {
    // rsaEncryption (1.2.840.113549.1.1.1)
    const rsa = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    if (_bytesEqual(oidBytes, rsa)) return 'rsaEncryption';
    return null;
  }

  static String? _parseName(Uint8List bytes) {
    final parts = <String>[];
    for (final set in _BerReader(bytes).readAllTlvs()) {
      if (set.tag != 0x31) continue;
      for (final seq in _BerReader(set.value).readAllTlvs()) {
        if (seq.tag != 0x30) continue;
        for (final atv in _BerReader(seq.value).readAllTlvs()) {
          if (atv.tag != 0x30) continue;
          final av = _BerReader(atv.value).readAllTlvs();
          if (av.length >= 2 && av[0].tag == 0x06 && av[1].tag == 0x0C) {
            final oid = av[0].value;
            final value = String.fromCharCodes(av[1].value);
            final label = _attributeLabel(oid);
            if (label != null) parts.add('$label=$value');
          }
        }
      }
    }
    return parts.isEmpty ? null : parts.join(', ');
  }

  static String? _attributeLabel(Uint8List oid) {
    const cn = [0x55, 0x04, 0x03];
    const email = [0x1a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];
    if (_bytesEqual(oid, cn)) return 'CN';
    if (_bytesEqual(oid, email)) return 'emailAddress';
    return null;
  }

  static int _parseInteger(Uint8List value) {
    if (value.isEmpty) return 0;
    var result = 0;
    for (final b in value) {
      result = (result << 8) | b;
    }
    return result;
  }

  static String _integerToHex(Uint8List value) {
    if (value.isEmpty) return '';
    // Strip leading zero byte used for positive INTEGER sign bit.
    var start = 0;
    while (start < value.length - 1 && value[start] == 0) {
      start++;
    }
    return SmimeCertId.normalize(
      value
          .sublist(start)
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join(),
    );
  }

  static String _octetsToHex(Uint8List value) =>
      SmimeCertId.normalize(
        value.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      );

  static int _indexOfSublist(Uint8List haystack, List<int> needle) {
    if (needle.isEmpty || haystack.length < needle.length) return -1;
    for (var i = 0; i <= haystack.length - needle.length; i++) {
      var found = true;
      for (var j = 0; j < needle.length; j++) {
        if (haystack[i + j] != needle[j]) {
          found = false;
          break;
        }
      }
      if (found) return i;
    }
    return -1;
  }

  static bool _bytesEqual(Uint8List a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

class _BerTlv {
  final int tag;
  final Uint8List value;
  const _BerTlv(this.tag, this.value);
}

class _BerReader {
  final Uint8List data;
  int offset;

  _BerReader(this.data, {this.start = 0}) : offset = start;

  final int start;

  bool get hasBytes => offset < data.length;

  int peekTag() => data[offset];

  List<_BerTlv> readAllTlvs() {
    final items = <_BerTlv>[];
    while (hasBytes) {
      items.add(readTlv());
    }
    return items;
  }

  _BerTlv readTlv() {
    final tag = _readTag();
    final length = _readLength();
    final end = offset + length;
    if (end > data.length) {
      throw FormatException('BER length exceeds buffer at offset $offset');
    }
    final value = Uint8List.sublistView(data, offset, end);
    offset = end;
    return _BerTlv(tag, value);
  }

  int _readTag() {
    var tag = data[offset++];
    if ((tag & 0x1F) != 0x1F) return tag;

    // High-tag-number form (not expected in CMS messages we handle).
    var value = 0;
    while (offset < data.length) {
      final b = data[offset++];
      value = (value << 7) | (b & 0x7F);
      if ((b & 0x80) == 0) break;
    }
    return value;
  }

  int _readLength() {
    final first = data[offset++];
    if (first < 0x80) return first;
    final count = first & 0x7F;
    var length = 0;
    for (var i = 0; i < count; i++) {
      length = (length << 8) | data[offset++];
    }
    return length;
  }
}
