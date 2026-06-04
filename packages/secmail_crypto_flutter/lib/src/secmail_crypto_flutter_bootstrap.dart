import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

import 'pgp_key_generation_params.dart';
import 'providers/openpgp/openpgp_crypto_provider.dart';
import 'storage/flutter_secure_storage_provider.dart';

/// Helpers to register Flutter/OpenPGP built-ins with [CryptoSdk].
abstract final class SecmailCryptoFlutter {
  /// OpenPGP + S/MIME providers (same as legacy auto-register, minus storage).
  static List<ICryptoProvider> defaultProviders({
    int openPgpPoolSize = 1,
    String smimeOpenSslPath = 'openssl',
    CryptoLogger logger = CryptoLogger.silent,
  }) {
    return [
      OpenPgpCryptoProvider(poolSize: openPgpPoolSize, logger: logger),
      SmimeCryptoProvider(opensslPath: smimeOpenSslPath, logger: logger),
    ];
  }

  /// [CryptoSdkConfig] with Flutter secure storage and OpenPGP + S/MIME providers.
  static CryptoSdkConfig config(CryptoSdkConfig base) {
    final logger = CryptoLogger(base.onLog);
    return CryptoSdkConfig(
      storageProvider:
          base.storageProvider ?? FlutterSecureStorageProvider(),
      executionStrategy: base.executionStrategy,
      providers: base.providers.isNotEmpty
          ? base.providers
          : defaultProviders(
              openPgpPoolSize: base.openPgpPoolSize,
              smimeOpenSslPath: base.smimeOpenSslPath,
              logger: logger,
            ),
      autoRegisterBuiltInProviders: base.autoRegisterBuiltInProviders,
      openPgpPoolSize: base.openPgpPoolSize,
      smimeOpenSslPath: base.smimeOpenSslPath,
      onLog: base.onLog,
    );
  }

  /// Initializes [CryptoSdk] with Flutter storage and OpenPGP + S/MIME providers.
  static CryptoSdk initialize([CryptoSdkConfig? config]) {
    return CryptoSdk.initialize(
      SecmailCryptoFlutter.config(config ?? CryptoSdkConfig()),
    );
  }
}
