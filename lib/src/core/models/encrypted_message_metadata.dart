import 'crypto_algorithm.dart';
import 'key_metadata.dart' show SmimeCertId;

/// Base sealed class for metadata extracted from encrypted messages.
///
/// Switch on the concrete subtype to access algorithm-specific fields:
/// ```dart
/// switch (metadata) {
///   case OpenPgpEncryptedMessageMetadata m => print(m.pkesks);
///   case SmimeEncryptedMessageMetadata m => print(m.recipients);
/// }
/// ```
sealed class EncryptedMessageMetadataBase {
  final CryptoAlgorithm algorithm;

  const EncryptedMessageMetadataBase({required this.algorithm});

  Map<String, dynamic> toMap();
}

/// Metadata extracted from an OpenPGP encrypted message.
///
/// Includes all [Public-Key Encrypted Session Key (PKESK)](https://datatracker.ietf.org/doc/html/rfc4880#section-5.1)
/// packets found in the message, plus other non-secret structural details
/// such as the symmetric cipher used for the payload.
final class OpenPgpEncryptedMessageMetadata
    extends EncryptedMessageMetadataBase {
  /// Armor block type when input was ASCII-armored (e.g. `"PGP MESSAGE"`).
  ///
  /// Null when [ciphertext] was already binary packet data.
  final String? armorType;

  /// All PKESK (tag 1) packets in wire order.
  final List<PkeskEntry> pkesks;

  /// Symmetric-key encrypted session key packets (tag 3), if any.
  final List<SkeskEntry> skesks;

  /// Symmetric cipher algorithm ID from the encrypted-data packet, if found.
  ///
  /// See RFC 4880 §9.2 for algorithm numbers (e.g. 7 = AES-128, 10 = AES-256).
  final int? symmetricCipherAlgorithm;

  /// Human-readable name for [symmetricCipherAlgorithm].
  final String? symmetricCipherAlgorithmName;

  /// Top-level packet tag numbers encountered while parsing (wire order).
  final List<int> packetTags;

  OpenPgpEncryptedMessageMetadata({
    this.armorType,
    required this.pkesks,
    this.skesks = const [],
    this.symmetricCipherAlgorithm,
    this.symmetricCipherAlgorithmName,
    this.packetTags = const [],
  }) : super(algorithm: CryptoAlgorithm.openPgp);

  /// All recipient key IDs from [pkesks] (one per PKESK packet, wire order).
  ///
  /// Multi-recipient messages contain multiple entries — one encrypted session
  /// key per recipient public key.
  List<String> get recipientKeyIds =>
      pkesks.map((p) => p.keyId).where((id) => id.isNotEmpty).toList();

  /// Short key IDs (last 32 bits) for each PKESK in [pkesks].
  List<String> get recipientKeyIdsShort =>
      pkesks.map((p) => p.keyIdShort).where((id) => id.isNotEmpty).toList();

  @override
  Map<String, dynamic> toMap() {
    return {
      'armorType': armorType,
      'pkesks': pkesks.map((p) => p.toMap()).toList(),
      'skesks': skesks.map((s) => s.toMap()).toList(),
      'symmetricCipherAlgorithm': symmetricCipherAlgorithm,
      'symmetricCipherAlgorithmName': symmetricCipherAlgorithmName,
      'packetTags': packetTags,
      'recipientKeyIds': recipientKeyIds,
      'recipientKeyIdsShort': recipientKeyIdsShort,
    };
  }
}

/// A parsed Public-Key Encrypted Session Key (PKESK) packet (OpenPGP tag 1).
final class PkeskEntry {
  /// PKESK packet version (typically 3).
  final int version;

  /// Full 64-bit recipient key ID as uppercase hex (16 characters).
  final String keyId;

  /// Short key ID — last 32 bits as uppercase hex (8 characters).
  final String keyIdShort;

  /// Decimal representation of the 64-bit key ID.
  final String keyIdNumeric;

  /// Public-key algorithm ID (RFC 4880 §9.1).
  final int publicKeyAlgorithm;

  /// Human-readable public-key algorithm name.
  final String publicKeyAlgorithmName;

  /// Length of the encrypted session key material in bytes (MPI payload).
  final int encryptedSessionKeyLength;

  const PkeskEntry({
    required this.version,
    required this.keyId,
    required this.keyIdShort,
    required this.keyIdNumeric,
    required this.publicKeyAlgorithm,
    required this.publicKeyAlgorithmName,
    required this.encryptedSessionKeyLength,
  });

  Map<String, dynamic> toMap() {
    return {
      'version': version,
      'keyId': keyId,
      'keyIdShort': keyIdShort,
      'keyIdNumeric': keyIdNumeric,
      'publicKeyAlgorithm': publicKeyAlgorithm,
      'publicKeyAlgorithmName': publicKeyAlgorithmName,
      'encryptedSessionKeyLength': encryptedSessionKeyLength,
    };
  }
}

/// A parsed Symmetric-Key Encrypted Session Key packet (OpenPGP tag 3).
final class SkeskEntry {
  /// SKESK packet version (typically 4 or 5).
  final int version;

  /// Symmetric cipher algorithm ID used to wrap the session key.
  final int symmetricAlgorithm;

  /// Human-readable symmetric algorithm name.
  final String symmetricAlgorithmName;

  /// S2K (string-to-key) type byte.
  final int s2kType;

  /// Human-readable S2K type name.
  final String s2kTypeName;

  const SkeskEntry({
    required this.version,
    required this.symmetricAlgorithm,
    required this.symmetricAlgorithmName,
    required this.s2kType,
    required this.s2kTypeName,
  });

  Map<String, dynamic> toMap() {
    return {
      'version': version,
      'symmetricAlgorithm': symmetricAlgorithm,
      'symmetricAlgorithmName': symmetricAlgorithmName,
      's2kType': s2kType,
      's2kTypeName': s2kTypeName,
    };
  }
}

// ── S/MIME ────────────────────────────────────────────────────────────────────

/// Metadata extracted from an S/MIME encrypted message (CMS EnvelopedData).
///
/// Includes all recipient info records (the CMS equivalent of OpenPGP PKESK
/// packets) plus non-secret structural details such as the content encryption
/// algorithm.
final class SmimeEncryptedMessageMetadata extends EncryptedMessageMetadataBase {
  /// CMS content type OID name (e.g. `"pkcs7-envelopedData"`).
  final String? cmsContentType;

  /// MIME `Content-Type` header value, if the input was a MIME message.
  final String? mimeContentType;

  /// MIME `smime-type` parameter (typically `"enveloped-data"`).
  final String? smimeType;

  /// All recipient info records found in the CMS structure (wire order).
  final List<SmimeRecipientInfoEntry> recipients;

  /// Content encryption algorithm name (e.g. `"aes-256-cbc"`).
  final String? contentEncryptionAlgorithm;

  /// Key length in bits for [contentEncryptionAlgorithm], when known.
  final int? contentEncryptionKeyLength;

  SmimeEncryptedMessageMetadata({
    this.cmsContentType,
    this.mimeContentType,
    this.smimeType,
    required this.recipients,
    this.contentEncryptionAlgorithm,
    this.contentEncryptionKeyLength,
  }) : super(algorithm: CryptoAlgorithm.smime);

  /// All recipient certificate IDs (one per CMS recipient info, wire order).
  ///
  /// Multi-recipient messages contain multiple entries. IDs are normalized via
  /// [SmimeCertId] and match [SmimePublicKeyMetadata.certId].
  List<String> get recipientCertIds => recipients
      .map((r) => r.certId)
      .whereType<String>()
      .where((id) => id.isNotEmpty)
      .toList();

  /// Short cert IDs (last 8 hex chars) for each recipient.
  List<String> get recipientCertIdsShort => recipients
      .map((r) => r.certIdShort)
      .whereType<String>()
      .where((id) => id.isNotEmpty)
      .toList();

  @override
  Map<String, dynamic> toMap() {
    return {
      'cmsContentType': cmsContentType,
      'mimeContentType': mimeContentType,
      'smimeType': smimeType,
      'recipients': recipients.map((r) => r.toMap()).toList(),
      'contentEncryptionAlgorithm': contentEncryptionAlgorithm,
      'contentEncryptionKeyLength': contentEncryptionKeyLength,
      'recipientCertIds': recipientCertIds,
      'recipientCertIdsShort': recipientCertIdsShort,
    };
  }
}

/// A parsed CMS recipient info record from an S/MIME encrypted message.
///
/// Analogous to [PkeskEntry] for OpenPGP — identifies who the message was
/// encrypted to without revealing the session key.
final class SmimeRecipientInfoEntry {
  /// CMS recipient info version.
  final int version;

  /// Recipient identifier type (e.g. `"issuerAndSerialNumber"`,
  /// `"subjectKeyIdentifier"`, `"keyAgreement"`).
  final String recipientType;

  /// Issuer distinguished name when available.
  final String? issuerDn;

  /// Certificate serial number (hex or colon-delimited), when available.
  final String? serialNumber;

  /// Subject Key Identifier as hex, when available.
  final String? subjectKeyIdentifier;

  /// Key encryption / key agreement algorithm (e.g. `"rsaEncryption"`).
  final String? keyEncryptionAlgorithm;

  /// Length of the encrypted key blob in bytes, when reported by the parser.
  final int? encryptedKeyLength;

  const SmimeRecipientInfoEntry({
    required this.version,
    required this.recipientType,
    this.issuerDn,
    this.serialNumber,
    this.subjectKeyIdentifier,
    this.keyEncryptionAlgorithm,
    this.encryptedKeyLength,
  });

  /// Canonical certificate identifier for lookup.
  ///
  /// Prefers normalized serial number; falls back to [subjectKeyIdentifier].
  /// Matches [SmimePublicKeyMetadata.certId] when the same cert was used.
  String? get certId {
    if (serialNumber != null && serialNumber!.isNotEmpty) {
      return SmimeCertId.fromSerial(serialNumber!);
    }
    if (subjectKeyIdentifier != null && subjectKeyIdentifier!.isNotEmpty) {
      return SmimeCertId.normalize(subjectKeyIdentifier!);
    }
    return null;
  }

  /// Short form of [certId] — last 8 hex characters.
  String? get certIdShort {
    final id = certId;
    return id == null ? null : SmimeCertId.shortFrom(id);
  }

  Map<String, dynamic> toMap() {
    return {
      'version': version,
      'recipientType': recipientType,
      'issuerDn': issuerDn,
      'serialNumber': serialNumber,
      'subjectKeyIdentifier': subjectKeyIdentifier,
      'keyEncryptionAlgorithm': keyEncryptionAlgorithm,
      'encryptedKeyLength': encryptedKeyLength,
      'certId': certId,
      'certIdShort': certIdShort,
    };
  }
}
