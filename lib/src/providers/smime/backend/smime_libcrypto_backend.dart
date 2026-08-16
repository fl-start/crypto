import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:openssl/openssl.dart' as openssl;

import '../../../core/logging/crypto_logger.dart';
import '../../../core/models/encrypted_message_metadata.dart';
import '../../../core/models/key_metadata.dart';
import '../parsing/cms_der_recipient_parser.dart';
import '../parsing/smime_text_helpers.dart';
import 'i_smime_backend.dart';
import 'openssl_ffi_helpers.dart';

/// S/MIME operations via OpenSSL libcrypto FFI ([package:openssl]).
class SmimeLibcryptoBackend implements ISmimeBackend {
  final CryptoLogger _log;

  SmimeLibcryptoBackend({CryptoLogger logger = CryptoLogger.silent})
    : _log = logger;

  @override
  Future<Uint8List> encrypt({
    required Uint8List data,
    required List<Uint8List> certificates,
  }) async {
    return using((arena) {
      final stack = x509StackFromPems(certificates, arena);
      final inBio = bioFromBytes(data, arena);
      final cms = openssl.CMS_encrypt(
        stack,
        inBio,
        openssl.EVP_aes_256_cbc(),
        openssl.CMS_BINARY,
      );
      opensslCheckNonNull(cms, 'CMS_encrypt failed');
      try {
        final outBio = newMemBio(arena);
        opensslCheck(
          openssl.SMIME_write_CMS(outBio, cms, nullptr, openssl.CMS_BINARY),
          'SMIME_write_CMS failed',
        );
        return readBio(outBio, arena);
      } finally {
        openssl.CMS_ContentInfo_free(cms);
      }
    });
  }

  @override
  Future<Uint8List> decrypt({
    required Uint8List encryptedData,
    required Uint8List privateKey,
  }) async {
    return using((arena) {
      final cms = _readCms(encryptedData, arena);
      try {
        final key = readPrivateKeyPem(privateKey, arena);
        final outBio = newMemBio(arena);
        openssl.CMS_decrypt_set1_pkey(cms, key, nullptr);
        opensslCheck(
          openssl.CMS_decrypt(cms, key, nullptr, nullptr, outBio, 0),
          'CMS_decrypt failed',
        );
        return readBio(outBio, arena);
      } finally {
        openssl.CMS_ContentInfo_free(cms);
      }
    });
  }

  Pointer<openssl.CMS_ContentInfo_st> _readCms(
    Uint8List encryptedData,
    Arena arena,
  ) {
    if (encryptedData.isNotEmpty && encryptedData.first == 0x30) {
      final derBio = bioFromBytes(encryptedData, arena);
      final cms = openssl.d2i_CMS_bio(derBio, nullptr);
      if (cms != nullptr) return cms;
    }
    final text = utf8.decode(encryptedData, allowMalformed: true);
    final smime = ensureSmimeText(normalizeSmimeText(text));
    final inBio = bioFromBytes(Uint8List.fromList(utf8.encode(smime)), arena);
    final cms = openssl.SMIME_read_CMS(inBio, nullptr);
    if (cms != nullptr) return cms;
    final fallback = openssl.d2i_CMS_bio(bioFromBytes(encryptedData, arena), nullptr);
    opensslCheckNonNull(fallback, 'Could not parse CMS (SMIME or DER)');
    return fallback;
  }

  Future<List<Uint8List>> extractCertificates(Uint8List cmsBytes) async {
    return using((arena) {
      final cms = _readCms(cmsBytes, arena);
      try {
        final stack = openssl.CMS_get1_certs(cms);
        if (stack == nullptr) return const <Uint8List>[];
        final n = openssl.OPENSSL_sk_num(stack.cast());
        final out = <Uint8List>[];
        for (var i = 0; i < n; i++) {
          final cert = openssl.OPENSSL_sk_value(stack.cast(), i).cast<openssl.x509_st>();
          if (cert == nullptr) continue;
          final bio = newMemBio(arena);
          opensslCheck(openssl.PEM_write_bio_X509(bio, cert), 'PEM_write_bio_X509 failed');
          out.add(readBio(bio, arena));
        }
        return out;
      } finally {
        openssl.CMS_ContentInfo_free(cms);
      }
    });
  }

  @override
  Future<Uint8List> sign({
    required Uint8List data,
    required Uint8List privateKey,
    required Uint8List signerCertificate,
  }) async {
    return using((arena) {
      final dataBio = bioFromBytes(data, arena);
      final cert = readX509Pem(signerCertificate, arena);
      final key = readPrivateKeyPem(privateKey, arena);
      final cms = openssl.CMS_sign(
        cert,
        key,
        nullptr,
        dataBio,
        openssl.CMS_BINARY,
      );
      opensslCheckNonNull(cms, 'CMS_sign failed');
      try {
        final outBio = newMemBio(arena);
        opensslCheck(
          openssl.SMIME_write_CMS(outBio, cms, dataBio, openssl.CMS_BINARY),
          'SMIME_write_CMS failed',
        );
        return readBio(outBio, arena);
      } finally {
        openssl.CMS_ContentInfo_free(cms);
      }
    });
  }

  @override
  Future<Uint8List> signDetachedRsaSha256({
    required Uint8List data,
    required Uint8List privateKey,
  }) async {
    return using((arena) {
      final md = openssl.EVP_sha256();
      opensslCheckNonNull(md, 'EVP_sha256 unavailable');
      final key = readPrivateKeyPem(privateKey, arena);
      final dataPtr = arena.allocate<Uint8>(data.isEmpty ? 1 : data.length);
      if (data.isNotEmpty) {
        dataPtr.asTypedList(data.length).setAll(0, data);
      }

      final ctx = openssl.EVP_MD_CTX_new();
      opensslCheckNonNull(ctx, 'EVP_MD_CTX_new failed');
      try {
        final pctx = arena<Pointer<openssl.evp_pkey_ctx_st>>();
        pctx.value = nullptr;
        opensslCheck(
          openssl.EVP_DigestSignInit(ctx, pctx, md, nullptr, key),
          'EVP_DigestSignInit failed',
        );
        if (pctx.value != nullptr) {
          opensslCheck(
            openssl.EVP_PKEY_CTX_set_rsa_padding(
              pctx.value,
              openssl.RSA_PKCS1_PADDING,
            ),
            'EVP_PKEY_CTX_set_rsa_padding failed',
          );
        }
        opensslCheck(
          openssl.EVP_DigestSignUpdate(ctx, dataPtr.cast(), data.length),
          'EVP_DigestSignUpdate failed',
        );

        final sigLen = arena<Size>();
        sigLen.value = 0;
        opensslCheck(
          openssl.EVP_DigestSign(ctx, nullptr, sigLen, nullptr, 0),
          'EVP_DigestSign length failed',
        );

        final sig = arena.allocate<Uint8>(sigLen.value);
        opensslCheck(
          openssl.EVP_DigestSign(
            ctx,
            sig.cast(),
            sigLen,
            dataPtr.cast(),
            data.length,
          ),
          'EVP_DigestSign failed',
        );
        return Uint8List.fromList(sig.asTypedList(sigLen.value));
      } finally {
        openssl.EVP_MD_CTX_free(ctx);
      }
    });
  }

  @override
  Future<bool> verify({
    required Uint8List data,
    required Uint8List signature,
    required Uint8List senderCertificate,
    Uint8List? caCertificate,
  }) async {
    return using((arena) {
      final sigBio = bioFromBytes(signature, arena);
      final dataBio = bioFromBytes(data, arena);
      final cms = openssl.SMIME_read_CMS(sigBio, nullptr);
      opensslCheckNonNull(cms, 'SMIME_read_CMS failed');
      try {
        final flags = openssl.CMS_NO_SIGNER_CERT_VERIFY | openssl.CMS_BINARY;
        final outBio = newMemBio(arena);
        opensslCheck(
          openssl.CMS_verify(cms, nullptr, nullptr, dataBio, outBio, flags),
          'CMS_verify failed',
        );
        return true;
      } finally {
        openssl.CMS_ContentInfo_free(cms);
      }
    });
  }

  @override
  Future<SmimeEncryptedMessageMetadata> parseEncryptedMessage(
    Uint8List encryptedData,
  ) async {
    try {
      final mimeText = utf8.decode(encryptedData, allowMalformed: true);
      final smime = ensureSmimeText(normalizeSmimeText(mimeText));
      final headers = parseSmimeMimeHeaders(smime);
      final pkcs7Der = extractPkcs7DerFromSmime(encryptedData);

      final recipients = pkcs7Der == null
          ? const <SmimeRecipientInfoEntry>[]
          : CmsDerRecipientParser.parseRecipientIds(pkcs7Der);

      final encAlgo = _contentEncryptionFromDer(pkcs7Der) ??
          (pkcs7Der != null ? 'aes-256-cbc' : null);

      return SmimeEncryptedMessageMetadata(
        cmsContentType: 'pkcs7-envelopedData',
        mimeContentType: headers.contentType,
        smimeType: headers.smimeType ?? 'enveloped-data',
        recipients: recipients,
        contentEncryptionAlgorithm: encAlgo,
        contentEncryptionKeyLength: _keyLengthFromAlgorithm(encAlgo),
      );
    } catch (e) {
      _log.warning('Error parsing S/MIME message', e);
      rethrow;
    }
  }

  @override
  Future<SmimePublicKeyMetadata> parseCertificate(Uint8List certificate) async {
    return using((arena) {
      final cert = readX509PemOrDer(certificate, arena);
      final subjectDn =
          x509NameToString(openssl.X509_get_subject_name(cert), arena) ?? '';
      final issuerDn =
          x509NameToString(openssl.X509_get_issuer_name(cert), arena) ?? '';

      final serialNumber = SmimeCertId.normalize(
        serialNumberHex(cert, arena) ?? '',
      );
      final notBefore = asn1TimeToUtcString(openssl.X509_get0_notBefore(cert));
      final notAfter = asn1TimeToUtcString(openssl.X509_get0_notAfter(cert));

      final pubkey = openssl.X509_get_pubkey(cert);
      var algo = 'rsaEncryption';
      var keyLength = 0;
      if (pubkey != nullptr) {
        keyLength = openssl.EVP_PKEY_get_bits(pubkey);
        final id = openssl.EVP_PKEY_get_id(pubkey);
        if (id == openssl.EVP_PKEY_EC) algo = 'id-ecPublicKey';
        openssl.EVP_PKEY_free(pubkey);
      }

      final sha256 = fingerprintHex(cert, openssl.EVP_sha256(), arena);
      final sha1 = fingerprintHex(cert, openssl.EVP_sha1(), arena);

      final cn = RegExp(r'CN=([^,/]+)').firstMatch(subjectDn)?.group(1)?.trim();
      final email = RegExp(
        r'(?:emailAddress|E)=([^,/]+)',
      ).firstMatch(subjectDn)?.group(1)?.trim();

      return SmimePublicKeyMetadata(
        subjectDn: subjectDn,
        issuerDn: issuerDn,
        serialNumber: serialNumber,
        validFrom: _parseOpenSslDate(notBefore),
        validTo: _parseOpenSslDate(notAfter),
        emailAddress: email,
        commonName: cn,
        publicKeyAlgorithm: algo,
        keyLength: keyLength,
        sha256Fingerprint: sha256,
        sha1Fingerprint: sha1,
        x509Version: 3,
        isSelfSigned: subjectDn == issuerDn,
        keyUsages: const [],
        extendedKeyUsages: const [],
      );
    });
  }

  @override
  Future<SmimePrivateKeyMetadata> parsePrivateKey(
    Uint8List privateKeyPem, {
    Uint8List? certificate,
  }) async {
    SmimePublicKeyMetadata? certMeta;
    if (certificate != null) {
      certMeta = await parseCertificate(certificate);
    }

    return using((arena) {
      final key = readPrivateKeyPem(privateKeyPem, arena);
      final bits = openssl.EVP_PKEY_get_bits(key);
      final id = openssl.EVP_PKEY_get_id(key);
      final algo = id == openssl.EVP_PKEY_EC ? 'id-ecPublicKey' : 'rsaEncryption';

      return SmimePrivateKeyMetadata(
        privateKeyAlgorithm: algo,
        keyLength: bits,
        associatedCertificate: certMeta,
      );
    });
  }

  String? _contentEncryptionFromDer(Uint8List? der) {
    if (der == null) return null;
    // AES-256-CBC (2.16.840.1.101.3.4.1.42) OID bytes in CMS EnvelopedData.
    const aes256Cbc = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];
    const aes128Cbc = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02];
    if (_derContains(der, aes256Cbc)) return 'aes-256-cbc';
    if (_derContains(der, aes128Cbc)) return 'aes-128-cbc';
    return null;
  }

  static bool _derContains(Uint8List der, List<int> needle) {
    for (var i = 0; i <= der.length - needle.length; i++) {
      var match = true;
      for (var j = 0; j < needle.length; j++) {
        if (der[i + j] != needle[j]) {
          match = false;
          break;
        }
      }
      if (match) return true;
    }
    return false;
  }

  int? _keyLengthFromAlgorithm(String? algorithm) {
    if (algorithm == null) return null;
    final lower = algorithm.toLowerCase();
    if (lower.contains('256')) return 256;
    if (lower.contains('128')) return 128;
    return null;
  }

  static DateTime _parseOpenSslDate(String? s) {
    if (s == null || s.isEmpty) return DateTime.utc(1970);
    final parts = s.trim().split(RegExp(r'\s+'));
    if (parts.length < 5) return DateTime.utc(1970);
    const months = {
      'Jan': 1,
      'Feb': 2,
      'Mar': 3,
      'Apr': 4,
      'May': 5,
      'Jun': 6,
      'Jul': 7,
      'Aug': 8,
      'Sep': 9,
      'Oct': 10,
      'Nov': 11,
      'Dec': 12,
    };
    final month = months[parts[0]] ?? 1;
    final day = int.tryParse(parts[1]) ?? 1;
    final time = parts[2].split(':');
    final year = int.tryParse(parts[3]) ?? 1970;
    return DateTime.utc(
      year,
      month,
      day,
      int.tryParse(time.elementAtOrNull(0) ?? '0') ?? 0,
      int.tryParse(time.elementAtOrNull(1) ?? '0') ?? 0,
      int.tryParse(time.elementAtOrNull(2) ?? '0') ?? 0,
    );
  }
}
