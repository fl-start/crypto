import 'dart:typed_data';

import '../../../core/models/encrypted_message_metadata.dart';
import '../../../core/models/key_metadata.dart';

/// Internal S/MIME crypto surface implemented by libcrypto (default) or CLI (tests).
abstract interface class ISmimeBackend {
  Future<Uint8List> encrypt({
    required Uint8List data,
    required List<Uint8List> certificates,
  });

  Future<Uint8List> decrypt({
    required Uint8List encryptedData,
    required Uint8List privateKey,
  });

  Future<Uint8List> sign({
    required Uint8List data,
    required Uint8List privateKey,
    required Uint8List signerCertificate,
  });

  Future<Uint8List> signDetachedRsaSha256({
    required Uint8List data,
    required Uint8List privateKey,
  });

  Future<bool> verify({
    required Uint8List data,
    required Uint8List signature,
    required Uint8List senderCertificate,
    Uint8List? caCertificate,
  });

  Future<SmimeEncryptedMessageMetadata> parseEncryptedMessage(
    Uint8List encryptedData,
  );

  Future<SmimePublicKeyMetadata> parseCertificate(Uint8List certificate);

  Future<SmimePrivateKeyMetadata> parsePrivateKey(
    Uint8List privateKeyPem, {
    Uint8List? certificate,
  });
}
