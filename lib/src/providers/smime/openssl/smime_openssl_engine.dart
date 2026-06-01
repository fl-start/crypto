import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../../../core/logging/crypto_logger.dart';
import '../../../core/models/encrypted_message_metadata.dart';
import '../../../core/models/key_metadata.dart';
import '../parsing/smime_message_parser.dart';

/// Low-level S/MIME operations backed by the system `openssl` CLI.
///
/// This class shells out to the `openssl smime` family of sub-commands and
/// communicates via temporary files (as required by OpenSSL's CLI interface).
/// All temp files are written to a unique system-temp sub-directory and
/// deleted in a `finally` block regardless of success or failure.
class SmimeOpensslEngine {
  /// Path to the `openssl` binary. Defaults to `'openssl'` (resolved via PATH).
  final String opensslPath;

  final CryptoLogger _log;

  SmimeOpensslEngine({
    this.opensslPath = 'openssl',
    CryptoLogger logger = CryptoLogger.silent,
  }) : _log = logger;

  // ── Encryption ─────────────────────────────────────────────────────────────

  /// Encrypts [data] with AES-256 for each certificate in [certificates].
  ///
  /// [certificates] should include the PEM certificate of every intended
  /// recipient (and optionally the sender, for decrypt-own-messages support).
  Future<Uint8List> encrypt({
    required Uint8List data,
    required List<Uint8List> certificates,
  }) async {
    final tmp = await _TempFiles.create();
    Uint8List? result;
    try {
      await tmp.write('data.txt', data);

      final certPaths = <String>[];
      for (int i = 0; i < certificates.length; i++) {
        final name = 'cert_$i.pem';
        await tmp.write(name, certificates[i]);
        certPaths.add(tmp.path(name));
      }

      final encryptedPath = tmp.path('encrypted.eml');
      final args = [
        'smime',
        '-encrypt',
        '-aes256',
        '-in',
        tmp.path('data.txt'),
        '-out',
        encryptedPath,
        ...certPaths,
      ];

      final processResult = await Process.run(opensslPath, args);
      if (processResult.exitCode != 0) {
        throw Exception('OpenSSL encryption failed: ${processResult.stderr}');
      }

      // Read fully into memory BEFORE the finally block attempts cleanup.
      // On Windows, deleting a file that still has an open handle yields
      // errno 32 ("file is being used by another process").
      result = await tmp.read('encrypted.eml');
    } finally {
      _log.debug('S/MIME encrypt: cleaning up ${tmp.dir.path}');
      await _safeCleanup(tmp, tag: 'encrypt');
    }
    // result is guaranteed non-null here: if the try block threw, the
    // finally ran and re-threw, so we never reach this line with null.
    return result;
  }

  // ── Decryption ─────────────────────────────────────────────────────────────

  /// Decrypts an S/MIME [encryptedData] (.p7m) message using [privateKey].
  Future<Uint8List> decrypt({
    required Uint8List encryptedData,
    required Uint8List privateKey,
  }) async {
    final tmp = await _TempFiles.create();
    Uint8List? result;
    try {
      final text = normalizeSmimeText(utf8.decode(encryptedData));
      final smime = ensureSmimeText(text);

      await tmp.write('encrypted_data.p7m', utf8.encode(smime));
      await tmp.write('private_key.pem', privateKey);

      final processResult = await Process.run(opensslPath, [
        'smime',
        '-decrypt',
        '-inform',
        'SMIME',
        '-in',
        tmp.path('encrypted_data.p7m'),
        '-inkey',
        tmp.path('private_key.pem'),
        '-out',
        tmp.path('decrypted_data.txt'),
      ], runInShell: true);

      if (processResult.exitCode != 0) {
        throw Exception('OpenSSL decryption failed: ${processResult.stderr}');
      }

      // Read fully into memory BEFORE finally cleanup (Windows file-lock fix).
      result = await tmp.read('decrypted_data.txt');
    } catch (e) {
      _log.error('S/MIME decryption error', e);
      rethrow;
    } finally {
      _log.debug('S/MIME decrypt: cleaning up ${tmp.dir.path}');
      await _safeCleanup(tmp, tag: 'decrypt');
    }
    return result;
  }

  // ── Signing ────────────────────────────────────────────────────────────────

  /// Creates a detached S/MIME signature over [data].
  ///
  /// [privateKey] is the signer's PEM private key.
  /// [signerCertificate] is the matching PEM X.509 certificate.
  Future<Uint8List> sign({
    required Uint8List data,
    required Uint8List privateKey,
    required Uint8List signerCertificate,
  }) async {
    final tmp = await _TempFiles.create();
    Uint8List? result;
    try {
      await tmp.write('data.pem', data);
      await tmp.write('private_key.pem', privateKey);
      await tmp.write('signer_certificate.pem', signerCertificate);

      _log.debug('S/MIME sign: key at ${tmp.path('private_key.pem')}');

      final processResult = await Process.run(opensslPath, [
        'smime',
        '-sign',
        '-in',
        tmp.path('data.pem'),
        '-signer',
        tmp.path('signer_certificate.pem'),
        '-inkey',
        tmp.path('private_key.pem'),
        '-out',
        tmp.path('signed_data.pem'),
        '-nodetach',
      ]);

      if (processResult.exitCode != 0) {
        throw Exception('OpenSSL signing failed: ${processResult.stderr}');
      }

      // Read fully into memory BEFORE finally cleanup (Windows file-lock fix).
      result = await tmp.read('signed_data.pem');
    } finally {
      _log.debug('S/MIME sign: cleaning up ${tmp.dir.path}');
      await _safeCleanup(tmp, tag: 'sign');
    }
    return result;
  }

  // ── Verification ───────────────────────────────────────────────────────────

  /// Verifies an S/MIME [signature] over [data].
  ///
  /// [senderCertificate] is the PEM X.509 certificate of the alleged signer.
  /// [caCertificate] is an optional CA certificate for chain validation.
  Future<bool> verify({
    required Uint8List data,
    required Uint8List signature,
    required Uint8List senderCertificate,
    Uint8List? caCertificate,
  }) async {
    final tmp = await _TempFiles.create();
    try {
      await tmp.write('data.pem', data);
      await tmp.write('signature.pem', signature);
      await tmp.write('sender_cert.pem', senderCertificate);
      if (caCertificate != null) {
        await tmp.write('ca_cert.pem', caCertificate);
      }

      final args = [
        'smime',
        '-verify',
        '-in',
        tmp.path('signature.pem'),
        '-content',
        tmp.path('data.pem'),
        '-certfile',
        tmp.path('sender_cert.pem'),
        '-noverify',
      ];
      if (caCertificate != null) {
        args.addAll(['-CAfile', tmp.path('ca_cert.pem')]);
      }

      final processResult = await Process.run(opensslPath, args);
      if (processResult.exitCode != 0) {
        throw Exception('OpenSSL verification failed: ${processResult.stderr}');
      }

      // verify() returns bool — no file to read, but we still need safe cleanup.
      return true;
    } finally {
      _log.debug('S/MIME verify: cleaning up ${tmp.dir.path}');
      await _safeCleanup(tmp, tag: 'verify');
    }
  }

  // ── Encrypted message inspection ───────────────────────────────────────────

  /// Parses an S/MIME [encryptedData] message and returns recipient metadata.
  ///
  /// Uses `openssl cms -cmsout -print` to inspect the CMS EnvelopedData
  /// structure without decrypting the payload.
  Future<SmimeEncryptedMessageMetadata> parseEncryptedMessage(
    Uint8List encryptedData,
  ) async {
    final tmp = await _TempFiles.create();
    try {
      final mimeText = utf8.decode(encryptedData, allowMalformed: true);
      final smime = ensureSmimeText(normalizeSmimeText(mimeText));
      await tmp.write('encrypted_data.p7m', utf8.encode(smime));
      final smimePath = tmp.path('encrypted_data.p7m');

      final cmsPrintOutput = await _obtainCmsPrintOutput(tmp, smimePath);
      final pkcs7Der = await _extractPkcs7Der(
        tmp,
        tmp.path('extracted.pkcs7.pem'),
      );

      return SmimeMessageParser.parse(
        cmsPrintOutput: cmsPrintOutput,
        mimeText: smime,
        pkcs7Der: pkcs7Der,
      );
    } catch (e) {
      print('Error parsing S/MIME message: $e');
      rethrow;
    } finally {
      await _safeCleanup(tmp, tag: 'parseEncryptedMessage');
    }
  }

  /// Obtains human-readable CMS structure text for an S/MIME message.
  ///
  /// Messages produced by `openssl smime -encrypt` are parsed most reliably by
  /// first extracting the PKCS#7 blob via `smime -pk7out`, then printing with
  /// `cms -print`. Direct `cms -inform SMIME` can return an empty structure on
  /// some OpenSSL builds (notably on Windows).
  Future<String> _obtainCmsPrintOutput(_TempFiles tmp, String smimePath) async {
    final pkcs7Path = tmp.path('extracted.pkcs7.pem');

    // Primary: smime -pk7out → cms -print (matches smime -encrypt output).
    final pkcs7Result = await Process.run(opensslPath, [
      'smime',
      '-inform',
      'SMIME',
      '-in',
      smimePath,
      '-pk7out',
      '-out',
      pkcs7Path,
    ]);
    if (pkcs7Result.exitCode == 0) {
      final printed = await _runCmsPrint(tmp.path('extracted.pkcs7.pem'));
      if (_hasRecipientData(printed)) return printed;
    }

    // Fallback: cms -inform SMIME directly on the MIME file.
    final direct = await _runCmsPrint(smimePath, inform: 'SMIME');
    if (_hasRecipientData(direct)) return direct;

    // Last resort: pkcs7 -print on the MIME wrapper.
    final pkcs7Print = await _runOpenSslPrint([
      'pkcs7',
      '-inform',
      'SMIME',
      '-in',
      smimePath,
      '-print',
      '-noout',
    ]);
    if (_hasRecipientData(pkcs7Print)) return pkcs7Print;

    // Return the best attempt so callers can still read content cipher etc.
    return direct.isNotEmpty ? direct : pkcs7Print;
  }

  Future<String> _runCmsPrint(String inputPath, {String inform = 'PEM'}) async {
    return _runOpenSslPrint([
      'cms',
      '-inform',
      inform,
      '-in',
      inputPath,
      '-cmsout',
      '-print',
    ]);
  }

  Future<String> _runOpenSslPrint(List<String> args) async {
    final result = await Process.run(opensslPath, args);
    if (result.exitCode != 0) {
      throw Exception('OpenSSL ${args.first} failed: ${result.stderr}');
    }
    return _combinedOutput(result);
  }

  String _combinedOutput(ProcessResult result) {
    final out = (result.stdout as String?) ?? '';
    final err = (result.stderr as String?) ?? '';
    if (out.trim().isNotEmpty) return out;
    return err;
  }

  bool _hasRecipientData(String cmsPrintOutput) {
    return cmsPrintOutput.contains('d.ktri:') ||
        cmsPrintOutput.contains('d.kari:') ||
        cmsPrintOutput.contains('recipientInfo:') ||
        cmsPrintOutput.contains('issuerAndSerialNumber:') ||
        cmsPrintOutput.contains('subjectKeyIdentifier:');
  }

  /// Exports the extracted PKCS#7 PEM blob to DER for binary recipient parsing.
  Future<Uint8List?> _extractPkcs7Der(
    _TempFiles tmp,
    String pkcs7PemPath,
  ) async {
    final derPath = tmp.path('extracted.pkcs7.der');
    final result = await Process.run(opensslPath, [
      'cms',
      '-inform',
      'PEM',
      '-in',
      pkcs7PemPath,
      '-outform',
      'DER',
      '-cmsout',
      '-out',
      derPath,
    ]);
    if (result.exitCode != 0) return null;
    try {
      return await tmp.read('extracted.pkcs7.der');
    } catch (_) {
      return null;
    }
  }

  // ── Key / certificate inspection ───────────────────────────────────────────

  /// Parses an X.509 PEM [certificate] and returns structured metadata.
  ///
  /// Runs three `openssl x509` subcommands in parallel:
  ///   1. `-text` — human-readable certificate dump for most fields.
  ///   2. `-fingerprint -sha256` — SHA-256 fingerprint.
  ///   3. `-fingerprint -sha1` — SHA-1 fingerprint.
  Future<SmimePublicKeyMetadata> parseCertificate(Uint8List certificate) async {
    final tmp = await _TempFiles.create();
    try {
      await tmp.write('cert.pem', certificate);
      final certPath = tmp.path('cert.pem');

      // Run all three commands in parallel.
      final results = await Future.wait([
        Process.run(opensslPath, ['x509', '-text', '-noout', '-in', certPath]),
        Process.run(opensslPath, [
          'x509',
          '-fingerprint',
          '-sha256',
          '-noout',
          '-in',
          certPath,
        ]),
        Process.run(opensslPath, [
          'x509',
          '-fingerprint',
          '-sha1',
          '-noout',
          '-in',
          certPath,
        ]),
      ]);

      for (final r in results) {
        if (r.exitCode != 0) {
          throw Exception('openssl x509 failed: ${r.stderr}');
        }
      }

      final text = results[0].stdout as String;
      final sha256Line = results[1].stdout as String;
      final sha1Line = results[2].stdout as String;

      return _parseX509Text(text, sha256Line.trim(), sha1Line.trim());
    } finally {
      await _safeCleanup(tmp, tag: 'parseCertificate');
    }
  }

  /// Parses PEM RSA/EC [privateKeyPem] and returns structured metadata.
  ///
  /// Uses `openssl pkey -text -noout` to extract the algorithm and key size.
  Future<SmimePrivateKeyMetadata> parsePrivateKey(
    Uint8List privateKeyPem, {
    Uint8List? certificate,
  }) async {
    final tmp = await _TempFiles.create();
    try {
      await tmp.write('key.pem', privateKeyPem);

      final result = await Process.run(opensslPath, [
        'pkey',
        '-text',
        '-noout',
        '-in',
        tmp.path('key.pem'),
      ]);
      if (result.exitCode != 0) {
        throw Exception('openssl pkey failed: ${result.stderr}');
      }

      final text = result.stdout as String;
      final (algo, bits) = _parsePrivateKeyText(text);

      SmimePublicKeyMetadata? certMeta;
      if (certificate != null) {
        certMeta = await parseCertificate(certificate);
      }

      return SmimePrivateKeyMetadata(
        privateKeyAlgorithm: algo,
        keyLength: bits,
        associatedCertificate: certMeta,
      );
    } finally {
      await _safeCleanup(tmp, tag: 'parsePrivateKey');
    }
  }

  // ── Parsing helpers ─────────────────────────────────────────────────────────

  SmimePublicKeyMetadata _parseX509Text(
    String text,
    String sha256Line,
    String sha1Line,
  ) {
    // Version: e.g. "Version: 3 (0x2)"
    final version =
        int.tryParse(
          RegExp(r'Version:\s+(\d+)').firstMatch(text)?.group(1) ?? '3',
        ) ??
        3;

    // Serial: "Serial Number:\n    ab:cd:ef" or inline
    final serialMatch = RegExp(
      r'Serial Number:\s*\n\s*([\da-fA-F:]+)',
      multiLine: true,
    ).firstMatch(text);
    final serialInline = RegExp(
      r'Serial Number:\s+([\da-fA-F:]+)',
    ).firstMatch(text);
    final serialNumber = (serialMatch?.group(1) ?? serialInline?.group(1) ?? '')
        .trim();

    // Issuer / Subject
    final issuerDn =
        RegExp(r'Issuer:\s+(.+)').firstMatch(text)?.group(1)?.trim() ?? '';
    final subjectDn =
        RegExp(r'Subject:\s+(.+)').firstMatch(text)?.group(1)?.trim() ?? '';

    // Common name from subject
    final cn = RegExp(
      r'CN\s*=\s*([^,\n]+)',
    ).firstMatch(subjectDn)?.group(1)?.trim();

    // emailAddress from subject DN or SAN
    final emailFromSubject = RegExp(
      r'(?:emailAddress|E)\s*=\s*([^\s,\n]+)',
    ).firstMatch(subjectDn)?.group(1)?.trim();
    final emailFromSan = RegExp(
      r'email:([^\s,\n]+)',
    ).firstMatch(text)?.group(1)?.trim();
    final emailAddress = emailFromSubject ?? emailFromSan;

    // Validity dates
    final notBefore =
        RegExp(r'Not Before:\s+(.+GMT)').firstMatch(text)?.group(1)?.trim() ??
        '';
    final notAfter =
        RegExp(r'Not After\s*:\s+(.+GMT)').firstMatch(text)?.group(1)?.trim() ??
        '';

    // Public key algorithm and bit size
    final pkAlgo =
        RegExp(
          r'Public Key Algorithm:\s+(\S+)',
        ).firstMatch(text)?.group(1)?.trim() ??
        '';
    final bitMatch = RegExp(
      r'(?:Public-Key|RSA Public-Key):\s+\((\d+)\s+bit\)',
    ).firstMatch(text);
    final keyLength = int.tryParse(bitMatch?.group(1) ?? '0') ?? 0;

    // Key usages
    final kuMatch = RegExp(
      r'X509v3 Key Usage:.*?\n\s+(.+)',
      multiLine: true,
    ).firstMatch(text);
    final keyUsages =
        kuMatch
            ?.group(1)
            ?.split(',')
            .map((s) => s.trim())
            .where((s) => s.isNotEmpty)
            .toList() ??
        const [];

    // Extended key usages
    final ekuMatch = RegExp(
      r'X509v3 Extended Key Usage:.*?\n\s+(.+)',
      multiLine: true,
    ).firstMatch(text);
    final extendedKeyUsages =
        ekuMatch
            ?.group(1)
            ?.split(',')
            .map((s) => s.trim())
            .where((s) => s.isNotEmpty)
            .toList() ??
        const [];

    // Fingerprints: "SHA256 Fingerprint=AB:CD:..."
    final sha256 =
        RegExp(
          r'(?:SHA256|sha256)\s+Fingerprint\s*=\s*(.+)',
          caseSensitive: false,
        ).firstMatch(sha256Line)?.group(1)?.trim() ??
        '';
    final sha1 =
        RegExp(
          r'(?:SHA1|sha1)\s+Fingerprint\s*=\s*(.+)',
          caseSensitive: false,
        ).firstMatch(sha1Line)?.group(1)?.trim() ??
        '';

    final skiRaw = RegExp(
      r'X509v3 Subject Key Identifier:\s*\n\s*([0-9a-fA-F:]+)',
      multiLine: true,
    ).firstMatch(text)?.group(1)?.trim();
    final subjectKeyIdentifier = skiRaw == null || skiRaw.isEmpty
        ? null
        : SmimeCertId.normalize(skiRaw);

    return SmimePublicKeyMetadata(
      subjectDn: subjectDn,
      issuerDn: issuerDn,
      serialNumber: serialNumber,
      subjectKeyIdentifier: subjectKeyIdentifier,
      validFrom: _parseX509Date(notBefore),
      validTo: _parseX509Date(notAfter),
      emailAddress: emailAddress,
      commonName: cn,
      publicKeyAlgorithm: pkAlgo,
      keyLength: keyLength,
      sha256Fingerprint: sha256,
      sha1Fingerprint: sha1,
      x509Version: version,
      isSelfSigned: subjectDn == issuerDn,
      keyUsages: keyUsages,
      extendedKeyUsages: extendedKeyUsages,
    );
  }

  /// Parses `openssl pkey -text` output and returns `(algorithm, bitLength)`.
  (String, int) _parsePrivateKeyText(String text) {
    // e.g. "Private-Key: (2048 bit, 2 primes)" or "RSA Private-Key: (2048 bit)"
    final bitMatch = RegExp(r'\((\d+)\s+bit').firstMatch(text);
    final bits = int.tryParse(bitMatch?.group(1) ?? '0') ?? 0;

    String algo = 'rsaEncryption';
    if (text.contains('EC') || text.contains('ECDSA')) {
      algo = 'id-ecPublicKey';
    } else if (text.contains('DSA')) {
      algo = 'dsaEncryption';
    }
    return (algo, bits);
  }

  static const _months = {
    'Jan': 1,
    'Feb': 2,
    'Mar': 3,
    'Apr': 4,
    'May': 5,
    'Jun': 6,
    'Jul': 7,
    'Aug': 8,
    'Sep': 9,
    'Oct': 10,
    'Nov': 11,
    'Dec': 12,
  };

  /// Parses an OpenSSL date string like `"Jan  1 00:00:00 2024 GMT"`.
  static DateTime _parseX509Date(String s) {
    final parts = s.trim().split(RegExp(r'\s+'));
    if (parts.length < 5) return DateTime.utc(1970);
    final month = _months[parts[0]] ?? 1;
    final day = int.tryParse(parts[1]) ?? 1;
    final time = parts[2].split(':');
    final year = int.tryParse(parts[3]) ?? 1970;
    return DateTime.utc(
      year,
      month,
      day,
      int.tryParse(time[0]) ?? 0,
      int.tryParse(time[1]) ?? 0,
      int.tryParse(time[2]) ?? 0,
    );
  }

  // ── Shared helpers ─────────────────────────────────────────────────────────

  /// Attempts to delete the temp directory up to [maxRetries] times with an
  /// exponential back-off between attempts.
  ///
  /// On Windows, the OS may hold a short-lived lock on a file even after the
  /// process that wrote/read it has exited (errno 32). Retrying with a small
  /// delay reliably resolves this without propagating a spurious error to the
  /// caller.
  ///
  /// Cleanup failure is logged as a warning and then swallowed — a leaked temp
  /// directory must never mask a successful crypto result or an intentional
  /// crypto exception.
  Future<void> _safeCleanup(_TempFiles tmp, {required String tag}) async {
    const maxRetries = 5;
    for (int attempt = 0; attempt < maxRetries; attempt++) {
      try {
        await tmp.cleanup();
        return; // success
      } catch (e) {
        if (attempt == maxRetries - 1) {
          _log.warning(
            'S/MIME $tag: temp cleanup failed after $maxRetries attempts '
            '(path=${tmp.dir.path}): $e',
          );
          return; // swallow — do not rethrow
        }
        // Exponential back-off: 100 ms, 200 ms, 300 ms, 400 ms …
        await Future.delayed(Duration(milliseconds: 100 * (attempt + 1)));
      }
    }
  }
}

// ── S/MIME text normalization helpers ─────────────────────────────────────

/// Normalises line endings, removes trailing whitespace, and rebuilds the
/// MIME message with exactly one blank line separating headers from body.
///
/// This produces the CRLF-delimited format that OpenSSL's S/MIME parser
/// expects.
String normalizeSmimeText(String input) {
  // 1. Normalise line endings.
  var s = input.replaceAll('\r\n', '\n').replaceAll('\r', '\n');

  // 2. Strip trailing whitespace from each line.
  s = s.split('\n').map((l) => l.trimRight()).join('\n');

  // 3. Split at the first blank line (header / body boundary).
  final parts = s.split(RegExp(r'\n\s*\n+'));
  if (parts.length < 2) return input;

  final headerLines = parts.first
      .split('\n')
      .map((l) => l.trim())
      .where((l) => l.isNotEmpty)
      .toList();

  final bodyLines = parts
      .sublist(1)
      .join('\n')
      .split('\n')
      .map((l) => l.trim())
      .where((l) => l.isNotEmpty)
      .toList();

  // 4. Rebuild with CRLF line endings and exactly one blank separator.
  final rebuilt = [
    ...headerLines,
    '', // exactly one blank line
    ...bodyLines,
    '', // trailing newline
  ].join('\r\n');

  return rebuilt;
}

/// Ensures the text has proper S/MIME MIME headers.
///
/// If headers are already present, delegates to [normalizeSmimeText].
/// Otherwise wraps the raw base64 payload in standard S/MIME headers.
String ensureSmimeText(String input) {
  final s = input.replaceAll('\r\n', '\n').replaceAll('\r', '\n').trim();

  if (s.toLowerCase().contains('content-type:')) {
    return normalizeSmimeText(s);
  }

  // Assume it is a bare PKCS#7 base64 blob.
  final b64 = s.replaceAll(RegExp(r'[^A-Za-z0-9+/=]'), '');

  // Wrap to 64-char lines (OpenSSL-friendly).
  final lines = <String>[];
  for (var i = 0; i < b64.length; i += 64) {
    lines.add(b64.substring(i, (i + 64).clamp(0, b64.length)));
  }

  return [
    'MIME-Version: 1.0',
    'Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="smime.p7m"',
    '',
    ...lines,
    '',
  ].join('\r\n');
}

// ── Temp file management ───────────────────────────────────────────────────

class _TempFiles {
  final Directory dir;

  _TempFiles._(this.dir);

  static Future<_TempFiles> create() async {
    final dir = await Directory.systemTemp.createTemp('smime_sdk_');
    return _TempFiles._(dir);
  }

  String path(String name) => '${dir.path}/$name';

  Future<void> write(String name, Uint8List data) =>
      File(path(name)).writeAsBytes(data);

  Future<Uint8List> read(String name) => File(path(name)).readAsBytes();

  Future<void> cleanup() => dir.delete(recursive: true);
}
