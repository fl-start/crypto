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
