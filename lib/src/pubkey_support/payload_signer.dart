import 'dart:convert';
import 'dart:typed_data';

import '../core/models/crypto_algorithm.dart';
import '../core/models/crypto_key.dart';
import '../providers/smime/openssl/smime_openssl_engine.dart';
import '../sdk/crypto_sdk_impl.dart';
import 'algorithm_names.dart';
import 'encoding.dart';

/// Signs pubkey API payload strings using an initialized [CryptoSdk].
///
/// All signatures returned are **base64url without padding**, matching the
/// pubkey server contract for OpenPGP, S/MIME, upload proofs, and HTTP auth.
class PubkeyPayloadSigner {
  PubkeyPayloadSigner(
    this._sdk, {
    String opensslPath = 'openssl',
  }) : _smimeEngine = SmimeOpensslEngine(opensslPath: opensslPath);

  final CryptoSdk _sdk;
  final SmimeOpensslEngine _smimeEngine;

  /// Signs the exact `X-Auth-Payload` header value (base64url JSON).
  ///
  /// The server verifies the signature over this string, not the decoded JSON.
  Future<String> signAuthHeaderPayload({
    required String payloadB64,
    required CryptoKey signingPrivateKey,
    required String sigFamily,
    String? passphrase,
  }) =>
      signPayloadString(
        payloadString: payloadB64,
        signingPrivateKey: signingPrivateKey,
        sigFamily: sigFamily,
        passphrase: passphrase,
      );

  /// Detached signature over [payloadString], base64url-encoded for the server.
  ///
  /// - Upload / rotate / delete proofs: sign the raw JSON **string** field.
  /// - HTTP auth: pass the base64url `X-Auth-Payload` header as [payloadString].
  ///
  /// [sigFamily] must be [PubkeySigFamily.openPgp] or [PubkeySigFamily.smime].
  Future<String> signPayloadString({
    required String payloadString,
    required CryptoKey signingPrivateKey,
    required String sigFamily,
    String? passphrase,
  }) async {
    final payloadBytes = Uint8List.fromList(utf8.encode(payloadString));

    final signatureBytes = switch (sigFamily) {
      PubkeySigFamily.smime => await _signSmimeDetached(
          payloadBytes: payloadBytes,
          signingPrivateKey: signingPrivateKey,
        ),
      PubkeySigFamily.openPgp => await _sdk.sign(
          data: payloadBytes,
          signingKey: signingPrivateKey,
          algorithm: CryptoAlgorithm.openPgp,
          passphrase: passphrase,
        ),
      _ => throw ArgumentError('Unsupported sigFamily: $sigFamily'),
    };

    return encodeBase64Url(signatureBytes);
  }

  Future<Uint8List> _signSmimeDetached({
    required Uint8List payloadBytes,
    required CryptoKey signingPrivateKey,
  }) async {
    return _smimeEngine.signDetachedRsaSha256(
      data: payloadBytes,
      privateKey: signingPrivateKey.rawBytes,
    );
  }
}
