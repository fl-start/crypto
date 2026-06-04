import 'dart:convert';
import 'dart:typed_data';

import '../core/models/crypto_algorithm.dart';
import '../core/models/crypto_key.dart';
import '../sdk/crypto_sdk_impl.dart';
import 'algorithm_names.dart';
import 'encoding.dart';

/// Signs pubkey API payload strings using an initialized [CryptoSdk].
///
/// Used by [secmail_pubkey_sdk] for upload proofs and is separate from
/// HTTP signed-request headers (those also need canonical body hashing).
class PubkeyPayloadSigner {
  PubkeyPayloadSigner(this._sdk);

  final CryptoSdk _sdk;

  /// Detached signature over [payloadString], base64url-encoded for the server.
  ///
  /// [sigFamily] must be [PubkeySigFamily.openPgp] or [PubkeySigFamily.smime].
  Future<String> signPayloadString({
    required String payloadString,
    required CryptoKey signingPrivateKey,
    required String sigFamily,
    String? passphrase,
  }) async {
    final algorithm = switch (sigFamily) {
      PubkeySigFamily.openPgp => CryptoAlgorithm.openPgp,
      PubkeySigFamily.smime => CryptoAlgorithm.smime,
      _ => throw ArgumentError('Unsupported sigFamily: $sigFamily'),
    };

    final signature = await _sdk.sign(
      data: Uint8List.fromList(utf8.encode(payloadString)),
      signingKey: signingPrivateKey,
      algorithm: algorithm,
      passphrase: passphrase,
    );

    return encodeBase64Url(signature);
  }
}
