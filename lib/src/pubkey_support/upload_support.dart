import 'dart:convert';
import 'dart:typed_data';

import '../core/models/crypto_key.dart';
import '../key_protection/private_key_protection.dart';
import '../sdk/crypto_sdk_impl.dart';
import 'algorithm_catalog.dart';

/// Builds pubkey upload wire fields from [CryptoSdk] key material.
abstract final class PubkeyUploadSupport {
  /// Armored OpenPGP or PEM S/MIME certificate string for `publicKey`.
  static String publicKeyWireString(CryptoSdk sdk, CryptoKey publicKey) {
    return utf8.decode(sdk.exportPublicKey(key: publicKey));
  }

  /// Server `encryptedBlob` object from an [EncryptedPrivateKeyPayload].
  static Map<String, dynamic> encryptedBlobMap({
    required EncryptedPrivateKeyPayload payload,
    required String email,
    required String catalogName,
  }) {
    return payload.toMap(
      identity: email.trim().toLowerCase(),
      keyType: PubkeyAlgorithmCatalog.blobKeyTypeFor(catalogName),
    );
  }

  /// Encrypts [privateKey] bytes and returns the server blob map.
  static Future<Map<String, dynamic>> buildEncryptedBlob({
    required Uint8List privateKeyBytes,
    required String email,
    required String catalogName,
    required String backupPassword,
  }) async {
    final payload = await encryptPrivateKey(
      privateKey: privateKeyBytes,
      password: backupPassword,
    );
    return encryptedBlobMap(
      payload: payload,
      email: email,
      catalogName: catalogName,
    );
  }
}
