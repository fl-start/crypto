import '../core/models/crypto_algorithm.dart';
import '../core/models/crypto_key.dart';
import '../sdk/crypto_sdk_impl.dart';
import 'encoding.dart';

/// Completes pubkey upload decrypt-challenge proofs.
abstract final class PubkeyDecryptChallenge {
  /// Decrypts server [ciphertextBase64Url] and returns `challengeResponse`.
  static Future<String> decryptChallengeResponse({
    required CryptoSdk sdk,
    required CryptoKey privateKey,
    required String ciphertextBase64Url,
    String? passphrase,
  }) async {
    final ciphertext = decodeBase64Url(ciphertextBase64Url);
    final plaintext = await sdk.decrypt(
      ciphertext: ciphertext,
      privateKey: privateKey,
      algorithm: privateKey.algorithm,
      passphrase: passphrase,
    );
    return encodeBase64Url(plaintext);
  }
}
