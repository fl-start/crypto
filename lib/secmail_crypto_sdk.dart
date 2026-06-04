// SecMail Crypto SDK
// A self-contained Flutter package providing OpenPGP and S/MIME cryptographic
// operations via a unified provider-based API.
//
// Import only this file from consumer code:
//   import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';
// ── Public contracts (implement to extend the SDK) ─────────────────────────
export 'src/core/contracts/i_crypto_provider.dart';
export 'src/core/contracts/i_execution_strategy.dart';
export 'src/core/contracts/i_key_inspection_provider.dart';
export 'src/core/contracts/i_message_inspection_provider.dart';
export 'src/core/contracts/i_storage_provider.dart';
export 'src/core/contracts/i_certificate_signing_service.dart';

// ── Public models ──────────────────────────────────────────────────────────
export 'src/core/models/crypto_algorithm.dart';
export 'src/core/models/crypto_key.dart';
export 'src/core/models/key_generation_params.dart';
export 'src/core/models/encrypted_message_metadata.dart';
export 'src/core/models/key_metadata.dart';
export 'src/core/models/key_type.dart';
export 'src/core/models/signature_verification_result.dart';

// ── Exceptions ─────────────────────────────────────────────────────────────
export 'src/core/exceptions/crypto_exceptions.dart';

// ── Logging ────────────────────────────────────────────────────────────────
export 'src/core/logging/crypto_logger.dart'
    show CryptoLogLevel, CryptoLogCallback, CryptoLogger;

// ── Execution strategies ───────────────────────────────────────────────────
export 'src/execution/direct_execution_strategy.dart';
export 'src/execution/isolate_config.dart';
export 'src/execution/isolate_execution_strategy.dart';

// ── Built-in storage (pure Dart) ───────────────────────────────────────────
export 'src/storage/in_memory_storage_provider.dart';

// ── OpenPGP message parser (pure Dart; crypto ops in secmail_crypto_flutter) ─
export 'src/providers/openpgp/parsing/openpgp_message_parser.dart';

// ── Pubkey server helpers (no HTTP — see secmail_pubkey_sdk) ───────────────
export 'src/pubkey_support/algorithm_names.dart';
export 'src/pubkey_support/body_hash.dart';
export 'src/pubkey_support/encoding.dart';
export 'src/pubkey_support/payload_signer.dart';

// ── Built-in provider (S/MIME; OpenPGP via secmail_crypto_flutter) ─────────
export 'src/providers/smime/smime_crypto_provider.dart';

// ── Private key protection (PBKDF2 + AES-256-GCM backup cipher) ───────────
export 'src/key_protection/private_key_protection.dart';

// ── SDK entry point ────────────────────────────────────────────────────────
export 'src/sdk/crypto_sdk_config.dart';
export 'src/sdk/crypto_sdk_impl.dart';
