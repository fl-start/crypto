import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

import 'providers/openpgp/openpgp_crypto_provider.dart';
import 'storage/flutter_secure_storage_provider.dart';

/// Helpers to register Flutter/OpenPGP built-ins with [CryptoSdk].
abstract final class SecmailCryptoFlutter {
  /// OpenPGP provider (same as legacy auto-register, minus storage).
  static List<ICryptoProvider> defaultProviders({
    int openPgpPoolSize = 1,
    CryptoLogger logger = CryptoLogger.silent,
  }) {
    return [
      OpenPgpCryptoProvider(poolSize: openPgpPoolSize, logger: logger),
    ];
  }

  /// [CryptoSdkConfig] with Flutter secure storage and the OpenPGP provider.
  static CryptoSdkConfig config(CryptoSdkConfig base) {
    final logger = CryptoLogger(base.onLog);
    return CryptoSdkConfig(
      storageProvider: base.storageProvider ?? FlutterSecureStorageProvider(),
      executionStrategy: base.executionStrategy,
      providers: base.providers.isNotEmpty
          ? base.providers
          : defaultProviders(
              openPgpPoolSize: base.openPgpPoolSize,
              logger: logger,
            ),
      autoRegisterBuiltInProviders: base.autoRegisterBuiltInProviders,
      openPgpPoolSize: base.openPgpPoolSize,
      onLog: base.onLog,
    );
  }

  /// Initializes [CryptoSdk] with Flutter storage and the OpenPGP provider.
  static CryptoSdk initialize([CryptoSdkConfig? config]) {
    return CryptoSdk.initialize(
      SecmailCryptoFlutter.config(config ?? CryptoSdkConfig()),
    );
  }
}
