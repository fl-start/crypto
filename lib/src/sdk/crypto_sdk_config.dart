import '../core/contracts/i_crypto_provider.dart';
import '../core/contracts/i_execution_strategy.dart';
import '../core/contracts/i_storage_provider.dart';
import '../core/logging/crypto_logger.dart';
import '../execution/direct_execution_strategy.dart';

/// Immutable bootstrap configuration for [CryptoSdk].
///
/// Pass an instance to [CryptoSdk.initialize] once at application startup.
///
/// Example:
/// ```dart
/// final sdk = CryptoSdk.initialize(
///   CryptoSdkConfig(
///     storageProvider: InMemoryStorageProvider(),
///     providers: [SmimeCryptoProvider()],
/// // Flutter apps: use SecmailCryptoFlutter.initialize() from secmail_crypto_flutter.
///     onLog: (level, msg, [err]) => print('[$level] $msg ${err ?? ''}'),
///   ),
/// );
/// ```
class CryptoSdkConfig {
  /// Backend for SDK-managed key-pair storage.
  ///
  /// When null, [CryptoSdk.initialize] uses [InMemoryStorageProvider].
  final ISecureStorageProvider? storageProvider;

  /// Strategy used when the SDK dispatches crypto work on behalf of a provider.
  ///
  /// Providers that manage their own concurrency (OpenPGP, S/MIME) are not
  /// affected by this strategy — they always execute inline.
  ///
  /// Defaults to [DirectExecutionStrategy] (inline execution).
  final IExecutionStrategy executionStrategy;

  /// Providers registered at startup. Additional providers can be added at
  /// runtime via [CryptoSdk.registerProvider].
  final List<ICryptoProvider> providers;

  /// Registers built-in providers automatically when [providers] is empty.
  ///
  /// Enabled by default to keep consumer setup minimal.
  final bool autoRegisterBuiltInProviders;

  /// OpenPGP worker pool size (used by [SecmailCryptoFlutter] in the Flutter addon).
  final int openPgpPoolSize;

  /// `openssl` executable path used when the SDK auto-creates
  /// [SmimeCryptoProvider].
  final String smimeOpenSslPath;

  /// Optional log callback. Receives all SDK lifecycle and error events.
  ///
  /// Set to null to silence all logging (the default).
  final CryptoLogCallback? onLog;

  const CryptoSdkConfig({
    this.storageProvider,
    this.executionStrategy = const DirectExecutionStrategy(),
    this.providers = const [],
    this.autoRegisterBuiltInProviders = true,
    this.openPgpPoolSize = 1,
    this.smimeOpenSslPath = 'openssl',
    this.onLog,
  });
}
