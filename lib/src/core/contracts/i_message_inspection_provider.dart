import 'dart:typed_data';

import '../models/encrypted_message_metadata.dart';

/// Optional interface for providers that can introspect encrypted messages
/// without decrypting them.
///
/// Not every [ICryptoProvider] is required to implement this. Callers should
/// check via `provider is IMessageInspectionProvider` before use, or rely on
/// [CryptoSdk.parseEncryptedMessage] which throws [CryptoOperationException]
/// when the registered provider does not support message inspection.
abstract interface class IMessageInspectionProvider {
  /// Parses [ciphertext] and returns structured metadata.
  ///
  /// For OpenPGP this includes all PKESK packets (recipient key IDs,
  /// algorithms, etc.). For S/MIME this includes all CMS recipient info
  /// records (issuer/serial, SKI, key encryption algorithm, etc.).
  /// The session key itself is never returned.
  Future<EncryptedMessageMetadataBase> parseEncryptedMessage(
    Uint8List ciphertext,
  );
}
