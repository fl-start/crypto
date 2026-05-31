import 'crypto_algorithm.dart';
import 'key_type.dart';

/// Base sealed class for all key metadata returned by [IKeyInspectionProvider].
///
/// Switch on the concrete subtype to access algorithm-specific fields:
/// ```dart
/// switch (metadata) {
///   case OpenPgpPublicKeyMetadata m => print(m.fingerprint);
///   case OpenPgpPrivateKeyMetadata m => print(m.isEncrypted);
///   case SmimePublicKeyMetadata m => print(m.subjectDn);
///   case SmimePrivateKeyMetadata m => print(m.keyLength);
/// }
/// ```
sealed class KeyMetadataBase {
  final CryptoAlgorithm algorithm;
  final KeyType keyType;

  const KeyMetadataBase({required this.algorithm, required this.keyType});

  Map<String, dynamic> toMap();
}

// ── OpenPGP ──────────────────────────────────────────────────────────────────

/// Metadata for an OpenPGP public key.
///
/// Fields are extracted from the `openpgp` package's `PublicKeyMetadata`
/// object and serialized as a plain [Map] across the worker-isolate boundary
/// before being reconstructed via [fromMap].
final class OpenPgpPublicKeyMetadata extends KeyMetadataBase {
  /// Primary key algorithm string (e.g. `"EdDSA"`, `"RSA"`).
  final String algorithmName;

  final String keyId;
  final String keyIdShort;
  final String keyIdNumeric;
  final String fingerprint;

  /// Creation time string as returned by the `openpgp` package.
  final String creationTime;

  final bool isSubKey;
  final bool canSign;
  final bool canEncrypt;

  /// User IDs (name + email + comment) bound to this key.
  final List<PgpIdentity> identities;

  /// Encryption/signing subkeys bundled with the primary key.
  final List<OpenPgpPublicKeyMetadata> subKeys;

  OpenPgpPublicKeyMetadata._({
    required this.algorithmName,
    required this.keyId,
    required this.keyIdShort,
    required this.keyIdNumeric,
    required this.fingerprint,
    required this.creationTime,
    required this.isSubKey,
    required this.canSign,
    required this.canEncrypt,
    required this.identities,
    required this.subKeys,
  }) : super(algorithm: CryptoAlgorithm.openPgp, keyType: KeyType.publicKey);

  /// All key IDs for this keyring (primary + [subKeys]), upper-case hex.
  ///
  /// PKESK packets in encrypted messages typically reference the encryption
  /// subkey ID, not the primary key ID returned by [keyId] alone.
  List<String> get allKeyIds => [
        if (keyId.isNotEmpty) keyId,
        for (final sub in subKeys)
          if (sub.keyId.isNotEmpty) sub.keyId,
      ];

  /// Short key IDs (last 32 bits) for [allKeyIds].
  List<String> get allKeyIdsShort => [
        if (keyIdShort.isNotEmpty) keyIdShort,
        for (final sub in subKeys)
          if (sub.keyIdShort.isNotEmpty) sub.keyIdShort,
      ];

  /// Constructs from the serialized [Map] produced by the OpenPGP worker.
  factory OpenPgpPublicKeyMetadata.fromMap(Map<String, dynamic> map) {
    return OpenPgpPublicKeyMetadata._(
      algorithmName: map['algorithm'] as String? ?? '',
      keyId: map['keyId'] as String? ?? '',
      keyIdShort: map['keyIdShort'] as String? ?? '',
      keyIdNumeric: map['keyIdNumeric'] as String? ?? '',
      fingerprint: map['fingerprint'] as String? ?? '',
      creationTime: map['creationTime'] as String? ?? '',
      isSubKey: map['isSubKey'] as bool? ?? false,
      canSign: map['canSign'] as bool? ?? false,
      canEncrypt: map['canEncrypt'] as bool? ?? false,
      identities: _parseIdentities(map['identities']),
      subKeys: _parsePublicSubKeys(map['subKeys']),
    );
  }

  @override
  Map<String, dynamic> toMap() {
    return {
      'algorithmName': algorithmName,
      'keyId': keyId,
      'keyIdShort': keyIdShort,
      'keyIdNumeric': keyIdNumeric,
      'fingerprint': fingerprint,
      'creationTime': creationTime,
      'isSubKey': isSubKey,
      'canSign': canSign,
      'canEncrypt': canEncrypt,
      'identities': identities.map((id) => id.toMap()).toList(),
      'subKeys': subKeys.map((k) => k.toMap()).toList(),
    };
  }
}

/// Metadata for an OpenPGP private key.
///
/// Fields are extracted from the `openpgp` package's `PrivateKeyMetadata`
/// object and serialized across the worker-isolate boundary via [fromMap].
final class OpenPgpPrivateKeyMetadata extends KeyMetadataBase {
  final String keyId;
  final String keyIdShort;
  final String keyIdNumeric;
  final String fingerprint;

  /// Creation time string as returned by the `openpgp` package.
  final String creationTime;

  final bool isSubKey;

  /// Whether the private key is protected by a passphrase.
  final bool isEncrypted;

  final bool canSign;

  /// User IDs (name + email + comment) bound to this key.
  final List<PgpIdentity> identities;

  /// Subkeys bundled with the primary private key.
  final List<OpenPgpPrivateKeyMetadata> subKeys;

  OpenPgpPrivateKeyMetadata._({
    required this.keyId,
    required this.keyIdShort,
    required this.keyIdNumeric,
    required this.fingerprint,
    required this.creationTime,
    required this.isSubKey,
    required this.isEncrypted,
    required this.canSign,
    required this.identities,
    required this.subKeys,
  }) : super(algorithm: CryptoAlgorithm.openPgp, keyType: KeyType.privateKey);

  /// All key IDs for this keyring (primary + [subKeys]), upper-case hex.
  List<String> get allKeyIds => [
        if (keyId.isNotEmpty) keyId,
        for (final sub in subKeys)
          if (sub.keyId.isNotEmpty) sub.keyId,
      ];

  /// Constructs from the serialized [Map] produced by the OpenPGP worker.
  factory OpenPgpPrivateKeyMetadata.fromMap(Map<String, dynamic> map) {
    return OpenPgpPrivateKeyMetadata._(
      keyId: map['keyId'] as String? ?? '',
      keyIdShort: map['keyIdShort'] as String? ?? '',
      keyIdNumeric: map['keyIdNumeric'] as String? ?? '',
      fingerprint: map['fingerprint'] as String? ?? '',
      creationTime: map['creationTime'] as String? ?? '',
      isSubKey: map['isSubKey'] as bool? ?? false,
      isEncrypted: map['encrypted'] as bool? ?? false,
      canSign: map['canSign'] as bool? ?? false,
      identities: _parseIdentities(map['identities']),
      subKeys: _parsePrivateSubKeys(map['subKeys']),
    );
  }

  @override
  Map<String, dynamic> toMap() {
    return {
      'keyId': keyId,
      'keyIdShort': keyIdShort,
      'keyIdNumeric': keyIdNumeric,
      'fingerprint': fingerprint,
      'creationTime': creationTime,
      'isSubKey': isSubKey,
      'isEncrypted': isEncrypted,
      'canSign': canSign,
      'identities': identities.map((id) => id.toMap()).toList(),
      'subKeys': subKeys.map((k) => k.toMap()).toList(),
    };
  }
}

/// A structured OpenPGP identity (user ID) with name, email, and comment.
final class PgpIdentity {
  /// The raw user-ID string (e.g. `"Alice <alice@example.com>"`).
  final String id;
  final String name;
  final String email;
  final String comment;

  const PgpIdentity({
    required this.id,
    required this.name,
    required this.email,
    required this.comment,
  });

  @override
  String toString() => id;

  Map<String, dynamic> toMap() {
    return {'id': id, 'name': name, 'email': email, 'comment': comment};
  }
}

// ── S/MIME ────────────────────────────────────────────────────────────────────

/// Normalizes S/MIME certificate identifiers for lookup and matching.
///
/// Handles colon-delimited hex, `0x` prefixes, and uppercase normalization
/// so [SmimePublicKeyMetadata.certId] matches [SmimeRecipientInfoEntry.certId]
/// from encrypted messages.
abstract final class SmimeCertId {
  static String normalize(String value) {
    return value
        .replaceAll(':', '')
        .replaceAll(' ', '')
        .replaceFirst(RegExp(r'^0x', caseSensitive: false), '')
        .toUpperCase();
  }

  /// Builds a canonical cert ID from an X.509 serial number string.
  static String fromSerial(String serialNumber) => normalize(serialNumber);

  /// Last 8 hex characters of [certId] (analogous to OpenPGP [keyIdShort]).
  static String shortFrom(String certId) =>
      certId.length >= 8 ? certId.substring(certId.length - 8) : certId;
}

/// Metadata for an S/MIME public key (X.509 certificate).
///
/// Fields are parsed from `openssl x509 -text` output by [SmimeOpensslEngine].
final class SmimePublicKeyMetadata extends KeyMetadataBase {
  /// Subject distinguished name (e.g. `"CN=Alice, emailAddress=alice@…"`).
  final String subjectDn;

  /// Issuer distinguished name.
  final String issuerDn;

  /// Certificate serial number (colon-delimited hex string).
  final String serialNumber;

  /// X.509 Subject Key Identifier extension (uppercase hex, no colons), if present.
  final String? subjectKeyIdentifier;

  final DateTime validFrom;
  final DateTime validTo;

  /// Email address from Subject Alternative Name or subject `emailAddress` field.
  final String? emailAddress;

  /// Common name from the subject DN.
  final String? commonName;

  /// Public key algorithm string returned by OpenSSL (e.g. `"rsaEncryption"`).
  final String publicKeyAlgorithm;

  /// Key size in bits (e.g. `2048`).
  final int keyLength;

  /// SHA-256 fingerprint (colon-delimited hex, e.g. `"AB:CD:…"`).
  final String sha256Fingerprint;

  /// SHA-1 fingerprint (colon-delimited hex).
  final String sha1Fingerprint;

  /// X.509 version number (1, 2, or 3).
  final int x509Version;

  /// True when the certificate is self-signed (subject DN == issuer DN).
  final bool isSelfSigned;

  /// Key usages declared in the certificate extension (e.g. `"Digital Signature"`).
  final List<String> keyUsages;

  /// Extended key usages (e.g. `"E-mail Protection"`).
  final List<String> extendedKeyUsages;

  SmimePublicKeyMetadata({
    required this.subjectDn,
    required this.issuerDn,
    required this.serialNumber,
    this.subjectKeyIdentifier,
    required this.validFrom,
    required this.validTo,
    required this.emailAddress,
    required this.commonName,
    required this.publicKeyAlgorithm,
    required this.keyLength,
    required this.sha256Fingerprint,
    required this.sha1Fingerprint,
    required this.x509Version,
    required this.isSelfSigned,
    required this.keyUsages,
    required this.extendedKeyUsages,
  }) : super(algorithm: CryptoAlgorithm.smime, keyType: KeyType.publicKey);

  bool get isExpired => validTo.isBefore(DateTime.now().toUtc());

  /// Canonical certificate identifier for lookup (normalized serial number).
  ///
  /// Use this to match recipients parsed from encrypted S/MIME messages via
  /// [SmimeRecipientInfoEntry.certId].
  String get certId => SmimeCertId.fromSerial(serialNumber);

  /// Short form of [certId] — last 8 hex characters.
  String get certIdShort => SmimeCertId.shortFrom(certId);

  @override
  Map<String, dynamic> toMap() {
    return {
      'subjectDn': subjectDn,
      'issuerDn': issuerDn,
      'serialNumber': serialNumber,
      'subjectKeyIdentifier': subjectKeyIdentifier,
      'certId': certId,
      'certIdShort': certIdShort,
      'validFrom': validFrom,
      'validTo': validTo,
      'emailAddress': emailAddress,
      'commonName': commonName,
      'publicKeyAlgorithm': publicKeyAlgorithm,
      'keyLength': keyLength,
      'sha256Fingerprint': sha256Fingerprint,
      'sha1Fingerprint': sha1Fingerprint,
      'x509Version': x509Version,
      'isSelfSigned': isSelfSigned,
      'keyUsages': keyUsages,
      'extendedKeyUsages': extendedKeyUsages,
    };
  }
}

/// Metadata for an S/MIME private key.
///
/// The private key itself has minimal intrinsic metadata (algorithm + size).
/// If a certificate was bundled (via `CryptoKey.metadata['certificate']`),
/// its fully parsed metadata is available in [associatedCertificate].
final class SmimePrivateKeyMetadata extends KeyMetadataBase {
  /// Private key algorithm string returned by OpenSSL (e.g. `"rsaEncryption"`).
  final String privateKeyAlgorithm;

  /// Key size in bits (e.g. `2048`).
  final int keyLength;

  /// Metadata for the X.509 certificate bundled with this private key, if any.
  final SmimePublicKeyMetadata? associatedCertificate;

  SmimePrivateKeyMetadata({
    required this.privateKeyAlgorithm,
    required this.keyLength,
    this.associatedCertificate,
  }) : super(algorithm: CryptoAlgorithm.smime, keyType: KeyType.privateKey);

  @override
  Map<String, dynamic> toMap() {
    return {
      'privateKeyAlgorithm': privateKeyAlgorithm,
      'keyLength': keyLength,
      'associatedCertificate': associatedCertificate?.toMap(),
    };
  }
}

// ── Private helpers ───────────────────────────────────────────────────────────

List<PgpIdentity> _parseIdentities(dynamic raw) {
  if (raw == null) return const [];
  return (raw as List).map((e) {
    final m = Map<String, dynamic>.from(e as Map);
    return PgpIdentity(
      id: m['id'] as String? ?? '',
      name: m['name'] as String? ?? '',
      email: m['email'] as String? ?? '',
      comment: m['comment'] as String? ?? '',
    );
  }).toList();
}

List<OpenPgpPublicKeyMetadata> _parsePublicSubKeys(dynamic raw) {
  if (raw == null) return const [];
  return (raw as List)
      .map(
        (e) => OpenPgpPublicKeyMetadata.fromMap(
          Map<String, dynamic>.from(e as Map),
        ),
      )
      .toList();
}

List<OpenPgpPrivateKeyMetadata> _parsePrivateSubKeys(dynamic raw) {
  if (raw == null) return const [];
  return (raw as List)
      .map(
        (e) => OpenPgpPrivateKeyMetadata.fromMap(
          Map<String, dynamic>.from(e as Map),
        ),
      )
      .toList();
}
