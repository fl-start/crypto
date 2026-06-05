import 'dart:convert';
import 'dart:ffi';
import 'dart:math';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:openssl/openssl.dart' as openssl;

import '../../../core/contracts/i_certificate_signing_service.dart';
import '../../../core/logging/crypto_logger.dart';
import 'openssl_ffi_helpers.dart';

/// Generates RSA 2048 / X.509 key pairs via OpenSSL libcrypto FFI.
class SmimeLibcryptoCertGenerator {
  final ICertificateSigningService? signingService;
  final CryptoLogger _log;

  SmimeLibcryptoCertGenerator({
    this.signingService,
    CryptoLogger logger = CryptoLogger.silent,
  }) : _log = logger;

  Future<({Uint8List privateKey, String certificatePem})> generate({
    required String commonName,
    required String email,
  }) async {
    final material = _generateKeyMaterial(
      commonName: commonName,
      email: email,
      includeCsr: signingService != null,
    );

    if (signingService != null) {
      _log.debug('Attempting CA signing for $email');
      final csrPem = material.csrPem;
      if (csrPem == null) {
        throw StateError('CSR generation failed for CA signing ($email)');
      }
      final signedCert = await signingService!.signCsr(
        csrPem: csrPem,
        email: email,
        commonName: commonName,
      );
      if (signedCert != null) {
        _log.info('CA-signed certificate issued for $email');
        return (privateKey: material.privateKey, certificatePem: signedCert);
      }
      _log.warning(
        'CA signing returned null for $email — falling back to self-signed.',
      );
    }

    _log.info('Self-signed certificate generated for $email');
    return (
      privateKey: material.privateKey,
      certificatePem: material.selfSignedCertPem,
    );
  }

  ({Uint8List privateKey, String? csrPem, String selfSignedCertPem})
  _generateKeyMaterial({
    required String commonName,
    required String email,
    required bool includeCsr,
  }) {
    return using((arena) {
      final pkey = _generateRsa2048(arena);
      final privateKeyPem = _writePrivateKeyPem(pkey, arena);
      final csrPem = includeCsr
          ? _writeCsrPem(
              arena: arena,
              pkey: pkey,
              commonName: commonName,
              email: email,
            )
          : null;
      final certPem = _createSelfSignedCertificate(
        arena: arena,
        pkey: pkey,
        commonName: commonName,
        email: email,
      );
      return (
        privateKey: Uint8List.fromList(utf8.encode(privateKeyPem)),
        csrPem: csrPem,
        selfSignedCertPem: certPem,
      );
    });
  }

  Pointer<openssl.evp_pkey_st> _generateRsa2048(Arena arena) {
    final ctx = openssl.EVP_PKEY_CTX_new_id(openssl.EVP_PKEY_RSA, nullptr);
    opensslCheckNonNull(ctx, 'EVP_PKEY_CTX_new_id failed');
    try {
      opensslCheck(openssl.EVP_PKEY_keygen_init(ctx), 'EVP_PKEY_keygen_init failed');
      opensslCheck(
        openssl.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048),
        'EVP_PKEY_CTX_set_rsa_keygen_bits failed',
      );
      final keyPtr = arena<Pointer<openssl.evp_pkey_st>>();
      keyPtr.value = nullptr;
      opensslCheck(openssl.EVP_PKEY_keygen(ctx, keyPtr), 'EVP_PKEY_keygen failed');
      opensslCheckNonNull(keyPtr.value, 'EVP_PKEY_keygen returned null key');
      return keyPtr.value;
    } finally {
      openssl.EVP_PKEY_CTX_free(ctx);
    }
  }

  String _writePrivateKeyPem(Pointer<openssl.evp_pkey_st> pkey, Arena arena) {
    final bio = newMemBio(arena);
    opensslCheck(
      openssl.PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr),
      'PEM_write_bio_PrivateKey failed',
    );
    return utf8.decode(readBio(bio, arena));
  }

  String _writeCsrPem({
    required Arena arena,
    required Pointer<openssl.evp_pkey_st> pkey,
    required String commonName,
    required String email,
  }) {
    final req = openssl.X509_REQ_new();
    opensslCheckNonNull(req, 'X509_REQ_new failed');
    try {
      opensslCheck(openssl.X509_REQ_set_version(req, 0), 'X509_REQ_set_version failed');
      opensslCheck(openssl.X509_REQ_set_pubkey(req, pkey), 'X509_REQ_set_pubkey failed');
      final name = _buildSubjectName(arena, commonName: commonName, email: email);
      opensslCheck(
        openssl.X509_REQ_set_subject_name(req, name),
        'X509_REQ_set_subject_name failed',
      );
      opensslCheckPositive(
        openssl.X509_REQ_sign(req, pkey, openssl.EVP_sha256()),
        'X509_REQ_sign failed',
      );

      final bio = newMemBio(arena);
      opensslCheck(
        openssl.PEM_write_bio_X509_REQ(bio, req),
        'PEM_write_bio_X509_REQ failed',
      );
      return utf8.decode(readBio(bio, arena));
    } finally {
      openssl.X509_REQ_free(req);
    }
  }

  String _createSelfSignedCertificate({
    required Arena arena,
    required Pointer<openssl.evp_pkey_st> pkey,
    required String commonName,
    required String email,
  }) {
    final cert = openssl.X509_new();
    opensslCheckNonNull(cert, 'X509_new failed');
    try {
      opensslCheck(openssl.X509_set_version(cert, 2), 'X509_set_version failed');

      final serial = openssl.ASN1_INTEGER_new();
      opensslCheckNonNull(serial, 'ASN1_INTEGER_new failed');
      try {
        opensslCheck(
          openssl.ASN1_INTEGER_set(
            serial,
            Random.secure().nextInt(0x7FFFFFFF),
          ),
          'ASN1_INTEGER_set failed',
        );
        opensslCheck(openssl.X509_set_serialNumber(cert, serial), 'X509_set_serialNumber failed');
      } finally {
        openssl.ASN1_INTEGER_free(serial);
      }

      opensslCheck(openssl.X509_set_pubkey(cert, pkey), 'X509_set_pubkey failed');

      final subject = _buildSubjectName(arena, commonName: commonName, email: email);
      opensslCheck(openssl.X509_set_subject_name(cert, subject), 'X509_set_subject_name failed');

      opensslCheckNonNull(
        openssl.X509_gmtime_adj(openssl.X509_getm_notBefore(cert), 0),
        'X509_gmtime_adj notBefore failed',
      );
      opensslCheckNonNull(
        openssl.X509_gmtime_adj(openssl.X509_getm_notAfter(cert), 365 * 24 * 60 * 60),
        'X509_gmtime_adj notAfter failed',
      );

      final issuer = openssl.X509_NAME_dup(subject);
      opensslCheckNonNull(issuer, 'X509_NAME_dup failed');
      opensslCheck(openssl.X509_set_issuer_name(cert, issuer), 'X509_set_issuer_name failed');

      opensslCheckPositive(openssl.X509_sign(cert, pkey, openssl.EVP_sha256()), 'X509_sign failed');

      final bio = newMemBio(arena);
      opensslCheck(openssl.PEM_write_bio_X509(bio, cert), 'PEM_write_bio_X509 failed');
      return utf8.decode(readBio(bio, arena));
    } finally {
      openssl.X509_free(cert);
    }
  }

  Pointer<openssl.X509_name_st> _buildSubjectName(
    Arena arena, {
    required String commonName,
    required String email,
  }) {
    final name = openssl.X509_NAME_new();
    opensslCheckNonNull(name, 'X509_NAME_new failed');
    _addSubjectEntries(arena, name, commonName: commonName, email: email);
    return name;
  }

  void _addSubjectEntries(
    Arena arena,
    Pointer<openssl.X509_name_st> name, {
    required String commonName,
    required String email,
  }) {
    final cnPtr = commonName.toNativeUtf8(allocator: arena);
    opensslCheck(
      openssl.X509_NAME_add_entry_by_NID(
        name,
        openssl.NID_commonName,
        openssl.MBSTRING_ASC,
        cnPtr.cast(),
        -1,
        -1,
        0,
      ),
      'X509_NAME_add_entry_by_NID CN failed',
    );
    final emailPtr = email.toNativeUtf8(allocator: arena);
    opensslCheck(
      openssl.X509_NAME_add_entry_by_NID(
        name,
        openssl.NID_pkcs9_emailAddress,
        openssl.MBSTRING_ASC,
        emailPtr.cast(),
        -1,
        -1,
        0,
      ),
      'X509_NAME_add_entry_by_NID email failed',
    );
  }
}
