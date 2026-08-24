import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

/// New-format OpenPGP packet with a single-byte body length (< 192 bytes).
Uint8List _packet(int tag, Uint8List body) {
  if (body.length >= 192) {
    throw ArgumentError('Test helper only supports bodies < 192 bytes.');
  }
  return Uint8List.fromList([0xC0 | tag, body.length, ...body]);
}

String _armor(Uint8List binary) {
  final b64 = base64Encode(binary);
  final lines = <String>[];
  for (var i = 0; i < b64.length; i += 64) {
    lines.add(b64.substring(i, i + 64 > b64.length ? b64.length : i + 64));
  }
  return '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n${lines.join('\n')}\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----\n';
}

/// Reads exactly one leading new-format packet's (tag, body).
({int tag, Uint8List body}) _readOnePacket(Uint8List data) {
  final tag = data[0] & 0x3F;
  final len = data[1];
  return (tag: tag, body: Uint8List.sublistView(data, 2, 2 + len));
}

void main() {
  group('OpenPgpPublicKeyRepacker', () {
    test('extracts the primary key packet (tag 6), dropping UID/subkey', () {
      final uidBody = Uint8List.fromList(utf8.encode('Alice <alice@example.com>'));
      final primaryBody = Uint8List.fromList([4, 0, 0, 0, 1, 22, 9, ...List.filled(9, 0xAB), 0, 32, ...List.filled(32, 0xCD)]);
      final subkeyBody = Uint8List.fromList([4, 0, 0, 0, 2, 18, 10, ...List.filled(10, 0xEF), 0, 32, ...List.filled(32, 0x11), 3, 1, 8, 7]);

      final block = Uint8List.fromList([
        ..._packet(6, primaryBody),
        ..._packet(13, uidBody),
        ..._packet(14, subkeyBody),
      ]);

      final repacked = OpenPgpPublicKeyRepacker.repackPrimary(Uint8List.fromList(utf8.encode(_armor(block))));
      final parsed = _readOnePacket(repacked);

      expect(parsed.tag, 6);
      expect(parsed.body, equals(primaryBody));
    });

    test('works on raw binary input too, not only armored', () {
      final primaryBody = Uint8List.fromList([4, 0, 0, 0, 1, 22, 9, ...List.filled(9, 0xAB), 0, 32, ...List.filled(32, 0xCD)]);
      final block = _packet(6, primaryBody);

      final repacked = OpenPgpPublicKeyRepacker.repackPrimary(block);
      final parsed = _readOnePacket(repacked);

      expect(parsed.tag, 6);
      expect(parsed.body, equals(primaryBody));
    });

    test('throws when no primary public-key packet is present', () {
      final uidOnly = _packet(13, Uint8List.fromList(utf8.encode('Alice')));

      expect(
        () => OpenPgpPublicKeyRepacker.repackPrimary(uidOnly),
        throwsA(isA<KeyImportException>()),
      );
    });

    test('extracts the public-subkey packet (tag 14), re-tagged as tag 6', () {
      final primaryBody = Uint8List.fromList([4, 0, 0, 0, 1, 22, 9, ...List.filled(9, 0xAB), 0, 32, ...List.filled(32, 0xCD)]);
      final subkeyBody = Uint8List.fromList([4, 0, 0, 0, 2, 18, 10, ...List.filled(10, 0xEF), 0, 32, ...List.filled(32, 0x11), 3, 1, 8, 7]);

      final block = Uint8List.fromList([
        ..._packet(6, primaryBody),
        ..._packet(14, subkeyBody),
      ]);

      final repacked = OpenPgpPublicKeyRepacker.repackEncryptionSubkey(block);
      final parsed = _readOnePacket(repacked);

      expect(parsed.tag, 6);
      expect(parsed.body, equals(subkeyBody));
    });

    test('throws when no public-subkey packet is present', () {
      final primaryBody = Uint8List.fromList([4, 0, 0, 0, 1, 22, 9, ...List.filled(9, 0xAB), 0, 32, ...List.filled(32, 0xCD)]);

      expect(
        () => OpenPgpPublicKeyRepacker.repackEncryptionSubkey(_packet(6, primaryBody)),
        throwsA(isA<KeyImportException>()),
      );
    });

    test('toCertificateBinary keeps every packet byte-for-byte, unlike the repackers', () {
      final uidBody = Uint8List.fromList(utf8.encode('Alice <alice@example.com>'));
      final primaryBody = Uint8List.fromList([4, 0, 0, 0, 1, 22, 9, ...List.filled(9, 0xAB), 0, 32, ...List.filled(32, 0xCD)]);
      final sigBody = Uint8List.fromList([4, 0x18, 22, 8, ...List.filled(4, 0x99)]);
      final subkeyBody = Uint8List.fromList([4, 0, 0, 0, 2, 18, 10, ...List.filled(10, 0xEF), 0, 32, ...List.filled(32, 0x11), 3, 1, 8, 7]);

      final block = Uint8List.fromList([
        ..._packet(6, primaryBody),
        ..._packet(13, uidBody),
        ..._packet(2, sigBody),
        ..._packet(14, subkeyBody),
        ..._packet(2, sigBody),
      ]);

      final full = OpenPgpPublicKeyRepacker.toCertificateBinary(Uint8List.fromList(utf8.encode(_armor(block))));

      expect(full, equals(block));
    });
  });
}
