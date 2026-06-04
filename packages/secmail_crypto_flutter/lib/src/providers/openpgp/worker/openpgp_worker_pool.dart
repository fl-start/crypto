import 'dart:async';
import 'dart:isolate';
import 'dart:math';

import 'dart:typed_data';

import 'package:flutter/services.dart';

import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';
import 'openpgp_op.dart';

/// Persistent pool of OpenPGP worker isolates.
///
/// Replaces the per-call `compute(openPgp*)` pattern that paid 40–80 ms of
/// isolate-spawn + native-init overhead on every decrypt during sync.
///
/// Pool size is configurable via the [poolSize] constructor parameter (clamped
/// to 1–4). The first submit lazily spawns the isolates; they live for the
/// remainder of the process unless [shutdown] is called explicitly.
///
/// Jobs are dispatched in round-robin order across all workers.
class OpenPgpWorkerPool {
  /// The number of worker isolates to maintain.
  final int poolSize;

  final CryptoLogger _log;

  /// Creates a pool of [poolSize] worker isolates.
  ///
  /// [logger] is used for lifecycle log events. Pass [CryptoLogger.silent] to
  /// suppress all output.
  OpenPgpWorkerPool({required this.poolSize, required CryptoLogger logger})
      : _log = logger;

  final List<_OpenPgpWorker> _workers = [];
  int _rr = 0;
  Completer<void>? _startCompleter;

  /// Pre-warms the pool by spawning all worker isolates.
  ///
  /// Call this once during application startup so the first crypto operation
  /// does not incur the isolate spawn latency. Idempotent — subsequent calls
  /// return immediately.
  Future<void> ensureInitialized() => _ensureStarted();

  Future<void> _ensureStarted() async {
    if (_workers.isNotEmpty) return;
    if (_startCompleter != null) return _startCompleter!.future;

    final completer = Completer<void>();
    _startCompleter = completer;

    final n = poolSize.clamp(1, 4);
    for (int i = 0; i < n; i++) {
      final w = await _OpenPgpWorker.spawn(index: i);
      _workers.add(w);
    }
    _log.info('OpenPgpWorkerPool started with $n workers');

    completer.complete();
    _startCompleter = null;
  }

  _OpenPgpWorker _pickWorker() {
    final w = _workers[_rr % _workers.length];
    _rr = (_rr + 1) & 0x7fffffff;
    return w;
  }

  /// Submits [op] with [payload] to the next available worker.
  ///
  /// Lazily starts the pool on the first call. Returns the result produced by
  /// the worker isolate, or throws if the worker reports an error.
  Future<Object?> run({
    required OpenPgpOp op,
    required Map<String, Object?> payload,
  }) async {
    await _ensureStarted();
    return _pickWorker().submit(op: op, payload: payload);
  }

  /// Shuts down all worker isolates immediately.
  ///
  /// Any in-flight jobs will complete with an error. After shutdown,
  /// subsequent [run] calls will re-spawn the pool.
  Future<void> shutdown() async {
    for (final w in _workers) {
      await w.shutdown();
    }
    _workers.clear();
    _log.info('OpenPgpWorkerPool shut down');
  }
}

// ── Internal worker ────────────────────────────────────────────────────────

class _OpenPgpWorker {
  _OpenPgpWorker._(this._isolate, this._sendPort, this._bootstrapPort);

  static Future<_OpenPgpWorker> spawn({required int index}) async {
    final bootstrap = ReceivePort();
    final isolate = await Isolate.spawn(
      openPgpWorkerMain,
      bootstrap.sendPort,
      debugName: 'openpgp-worker-$index',
    );
    final completer = Completer<SendPort>();
    late final StreamSubscription<dynamic> sub;
    sub = bootstrap.listen((msg) {
      if (msg is SendPort && !completer.isCompleted) {
        completer.complete(msg);
        sub.cancel();
      }
    });
    final sendPort = await completer.future;
    return _OpenPgpWorker._(isolate, sendPort, bootstrap);
  }

  final Isolate _isolate;
  final SendPort _sendPort;
  final ReceivePort _bootstrapPort;
  final _inFlight = <String, Completer<Object?>>{};
  bool _bindingSent = false;

  Future<Object?> submit({
    required OpenPgpOp op,
    required Map<String, Object?> payload,
  }) {
    final reply = ReceivePort();
    final jobId = _newJobId();
    final completer = Completer<Object?>();
    _inFlight[jobId] = completer;

    final combined = <String, Object?>{...payload};
    if (!_bindingSent) {
      combined['_rootIsolateToken'] = ServicesBinding.rootIsolateToken;
      _bindingSent = true;
    }

    reply.listen((raw) {
      reply.close();
      final m = Map<dynamic, dynamic>.from(raw as Map);
      final id = m['jobId'] as String;
      final c = _inFlight.remove(id);
      if (c == null) return;
      if (m['success'] == true) {
        c.complete(m['result']);
      } else {
        c.completeError(
          StateError(m['error'] as String? ?? 'OpenPGP worker failed'),
        );
      }
    });

    _sendPort.send({
      'replyPort': reply.sendPort,
      'jobId': jobId,
      'op': op.name,
      'payload': combined,
    });

    return completer.future;
  }

  Future<void> shutdown() async {
    _bootstrapPort.close();
    _isolate.kill(priority: Isolate.immediate);
    for (final c in _inFlight.values) {
      if (!c.isCompleted) {
        c.completeError(StateError('OpenPGP worker shut down'));
      }
    }
    _inFlight.clear();
  }

  String _newJobId() {
    final now = DateTime.now().microsecondsSinceEpoch;
    final r = Random().nextInt(1 << 20);
    return 'pgp-$now-$r';
  }
}
