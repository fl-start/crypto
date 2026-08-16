import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:openssl/openssl.dart' as openssl;

void opensslCheck(int result, String message) {
  if (result != 1) {
    throw StateError('$message: ${opensslLastError()}');
  }
}

/// OpenSSL 3.x [X509_sign] / [X509_REQ_sign] may return a positive size, not 1.
void opensslCheckPositive(int result, String message) {
  if (result <= 0) {
    throw StateError('$message: ${opensslLastError()}');
  }
}

void opensslCheckNonNull<T extends NativeType>(Pointer<T>? ptr, String message) {
  if (ptr == null || ptr == nullptr) {
    throw StateError('$message: ${opensslLastError()}');
  }
}

String opensslLastError() {
  return using((arena) {
    final code = openssl.ERR_get_error();
    if (code == 0) return 'unknown OpenSSL error';
    final buf = arena.allocate<Char>(256);
    openssl.ERR_error_string_n(code, buf, 256);
    return buf.cast<Utf8>().toDartString();
  });
}

Pointer<openssl.bio_st> bioFromBytes(Uint8List bytes, Arena arena) {
  final inPtr = arena.allocate<Uint8>(bytes.isEmpty ? 1 : bytes.length);
  if (bytes.isNotEmpty) {
    inPtr.asTypedList(bytes.length).setAll(0, bytes);
  }
  final bio = openssl.BIO_new_mem_buf(
    inPtr.cast(),
    bytes.length,
  );
  opensslCheckNonNull(bio, 'BIO_new_mem_buf failed');
  return bio;
}

Uint8List readBio(Pointer<openssl.bio_st> bio, Arena arena) {
  final pending = openssl.BIO_ctrl_pending(bio);
  if (pending <= 0) return Uint8List(0);

  final buf = arena.allocate<Uint8>(pending);
  final read = openssl.BIO_read(bio, buf.cast(), pending);
  if (read <= 0) {
    throw StateError('BIO_read failed: ${opensslLastError()}');
  }
  return Uint8List.fromList(buf.asTypedList(read));
}

Pointer<openssl.evp_pkey_st> readPrivateKeyPem(
  Uint8List pemBytes,
  Arena arena,
) {
  final bio = bioFromBytes(pemBytes, arena);
  final keyPtr = arena<Pointer<openssl.evp_pkey_st>>();
  keyPtr.value = nullptr;

  final key = openssl.PEM_read_bio_PrivateKey(bio, keyPtr, nullptr, nullptr);
  if (key == nullptr) {
    throw StateError('PEM_read_bio_PrivateKey failed: ${opensslLastError()}');
  }
  return key;
}

Pointer<openssl.x509_st> readX509Pem(Uint8List pemBytes, Arena arena) {
  final bio = bioFromBytes(pemBytes, arena);
  final cert = openssl.PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  if (cert == nullptr) {
    throw StateError('PEM_read_bio_X509 failed: ${opensslLastError()}');
  }
  return cert;
}

bool looksLikePem(Uint8List bytes) {
  final probeLen = bytes.length < 256 ? bytes.length : 256;
  final probe = utf8.decode(bytes.sublist(0, probeLen), allowMalformed: true);
  return probe.contains('-----BEGIN');
}

Pointer<openssl.x509_st> readX509PemOrDer(Uint8List bytes, Arena arena) {
  if (looksLikePem(bytes)) {
    try {
      return readX509Pem(bytes, arena);
    } catch (_) {
      // Fall through to DER — some files wrap binary in text.
    }
  }
  final bio = bioFromBytes(bytes, arena);
  final cert = openssl.d2i_X509_bio(bio, nullptr);
  if (cert == nullptr) {
    throw StateError(
      'Could not parse X.509 certificate as PEM or DER: ${opensslLastError()}',
    );
  }
  return cert;
}

Uint8List x509ToPem(Pointer<openssl.x509_st> cert, Arena arena) {
  final bio = newMemBio(arena);
  opensslCheck(openssl.PEM_write_bio_X509(bio, cert), 'PEM_write_bio_X509 failed');
  return readBio(bio, arena);
}

Uint8List x509ToDer(Pointer<openssl.x509_st> cert, Arena arena) {
  final bio = newMemBio(arena);
  opensslCheck(openssl.i2d_X509_bio(bio, cert), 'i2d_X509_bio failed');
  return readBio(bio, arena);
}

Uint8List writePrivateKeyPem(
  Pointer<openssl.evp_pkey_st> pkey,
  Arena arena,
) {
  final bio = newMemBio(arena);
  opensslCheck(
    openssl.PEM_write_bio_PrivateKey(
      bio,
      pkey,
      nullptr,
      nullptr,
      0,
      nullptr,
      nullptr,
    ),
    'PEM_write_bio_PrivateKey failed',
  );
  return readBio(bio, arena);
}

Uint8List normalizeCertificateToPem(Uint8List bytes) {
  return using((arena) {
    final cert = readX509PemOrDer(bytes, arena);
    return x509ToPem(cert, arena);
  });
}

Uint8List certificateToDer(Uint8List pemOrDer) {
  return using((arena) {
    final cert = readX509PemOrDer(pemOrDer, arena);
    return x509ToDer(cert, arena);
  });
}

({Uint8List privateKeyPem, Uint8List certificatePem}) unpackPkcs12({
  required Uint8List pkcs12Bytes,
  required String password,
}) {
  return using((arena) {
    final bio = bioFromBytes(pkcs12Bytes, arena);
    final p12 = openssl.d2i_PKCS12_bio(bio, nullptr);
    opensslCheckNonNull(p12, 'd2i_PKCS12_bio failed');
    try {
      final pkeyPtr = arena<Pointer<openssl.evp_pkey_st>>();
      final certPtr = arena<Pointer<openssl.x509_st>>();
      pkeyPtr.value = nullptr;
      certPtr.value = nullptr;
      final passPtr = password.toNativeUtf8(allocator: arena);
      opensslCheck(
        openssl.PKCS12_parse(
          p12,
          passPtr.cast(),
          pkeyPtr,
          certPtr,
          nullptr,
        ),
        'PKCS12_parse failed',
      );
      final pkey = pkeyPtr.value;
      final cert = certPtr.value;
      if (pkey == nullptr || cert == nullptr) {
        throw StateError(
          'PKCS#12 did not contain both a private key and a certificate',
        );
      }
      try {
        return (
          privateKeyPem: writePrivateKeyPem(pkey, arena),
          certificatePem: x509ToPem(cert, arena),
        );
      } finally {
        openssl.EVP_PKEY_free(pkey);
        openssl.X509_free(cert);
      }
    } finally {
      openssl.PKCS12_free(p12);
    }
  });
}

Uint8List packPkcs12({
  required Uint8List privateKeyPem,
  required Uint8List certificatePem,
  required String password,
  String friendlyName = 'S/MIME',
}) {
  return using((arena) {
    final pkey = readPrivateKeyPem(privateKeyPem, arena);
    final cert = readX509PemOrDer(certificatePem, arena);
    final passPtr = password.toNativeUtf8(allocator: arena);
    final namePtr = friendlyName.toNativeUtf8(allocator: arena);
    final p12 = openssl.PKCS12_create(
      passPtr.cast(),
      namePtr.cast(),
      pkey,
      cert,
      nullptr,
      0,
      0,
      0,
      0,
      0,
    );
    opensslCheckNonNull(p12, 'PKCS12_create failed');
    try {
      final bio = newMemBio(arena);
      opensslCheck(openssl.i2d_PKCS12_bio(bio, p12), 'i2d_PKCS12_bio failed');
      return readBio(bio, arena);
    } finally {
      openssl.PKCS12_free(p12);
    }
  });
}

Pointer<openssl.stack_st_X509> x509StackFromPems(
  List<Uint8List> certificates,
  Arena arena,
) {
  final stack = openssl.OPENSSL_sk_new_null().cast<openssl.stack_st_X509>();
  opensslCheckNonNull(stack, 'OPENSSL_sk_new_null failed');

  for (final pem in certificates) {
    final cert = readX509Pem(pem, arena);
    if (openssl.OPENSSL_sk_push(stack.cast(), cert.cast()) < 0) {
      throw StateError('OPENSSL_sk_push failed: ${opensslLastError()}');
    }
  }
  return stack;
}

Pointer<openssl.bio_st> newMemBio(Arena arena) {
  final bio = openssl.BIO_new(openssl.BIO_s_mem());
  opensslCheckNonNull(bio, 'BIO_new failed');
  return bio;
}

String? asn1TimeToUtcString(Pointer<openssl.asn1_string_st> time) {
  if (time == nullptr) return null;
  return using((arena) {
    final bio = newMemBio(arena);
    opensslCheck(
      openssl.ASN1_TIME_print(bio, time),
      'ASN1_TIME_print failed',
    );
    final raw = readBio(bio, arena);
    return String.fromCharCodes(raw).trim();
  });
}

String? x509NameToString(Pointer<openssl.X509_name_st> name, Arena arena) {
  if (name == nullptr) return null;
  final line = openssl.X509_NAME_oneline(name, nullptr, 0);
  if (line == nullptr) return null;
  // Intentionally not freed: libc `free` is not exported on Windows prebuilts.
  return line.cast<Utf8>().toDartString();
}

String? serialNumberHex(Pointer<openssl.x509_st> cert, Arena arena) {
  final serial = openssl.X509_get_serialNumber(cert);
  if (serial == nullptr) return null;
  final len = openssl.ASN1_STRING_length(serial);
  if (len <= 0) return null;
  final data = openssl.ASN1_STRING_get0_data(serial);
  if (data == nullptr) return null;
  var start = 0;
  while (start < len - 1 && data[start] == 0) {
    start++;
  }
  final hex = StringBuffer();
  for (var i = start; i < len; i++) {
    hex.write(data[i].toRadixString(16).padLeft(2, '0'));
  }
  return hex.toString().toUpperCase();
}

String fingerprintHex(
  Pointer<openssl.x509_st> cert,
  Pointer<openssl.evp_md_st> md,
  Arena arena,
) {
  final size = openssl.EVP_MD_get_size(md);
  final out = arena.allocate<Uint8>(size);
  final len = arena<UnsignedInt>();
  len.value = size;

  opensslCheck(
    openssl.X509_digest(cert, md, out.cast(), len),
    'X509_digest failed',
  );

  return out
      .asTypedList(len.value)
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join(':')
      .toUpperCase();
}
