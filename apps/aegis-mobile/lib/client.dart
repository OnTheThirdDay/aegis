import 'dart:convert';

import 'package:flutter/services.dart';

/// A failed call, with a message for the user.
class ClientError implements Exception {
  ClientError(this.message);
  final String message;
  @override
  String toString() => message;
}

/// The enrolled device, if any.
class DeviceInfo {
  DeviceInfo({required this.enrolled, this.name, this.server, this.expiresAt});

  factory DeviceInfo.fromJson(Map<String, dynamic> j) => DeviceInfo(
        enrolled: j['enrolled'] == true,
        name: j['name'] as String?,
        server: j['server'] as String?,
        expiresAt: _time(j['certificate_expires_at']),
      );

  final bool enrolled;
  final String? name;
  final String? server;
  final DateTime? expiresAt;
}

enum ConnectionState { disconnected, connecting, connected }

/// Connection state and counters.
class Status {
  Status({
    this.state = ConnectionState.disconnected,
    this.error,
    this.info,
    this.server,
    this.since,
    this.bytesUp = 0,
    this.bytesDown = 0,
    this.connections = 0,
  });

  factory Status.fromJson(Map<String, dynamic> j) => Status(
        state: switch (j['state']) {
          'connected' => ConnectionState.connected,
          'connecting' => ConnectionState.connecting,
          _ => ConnectionState.disconnected,
        },
        error: j['error'] as String?,
        info: j['info'] as String?,
        server: j['server'] as String?,
        since: _time(j['connected_since']),
        bytesUp: (j['bytes_up'] as num?)?.toInt() ?? 0,
        bytesDown: (j['bytes_down'] as num?)?.toInt() ?? 0,
        connections: (j['connections'] as num?)?.toInt() ?? 0,
      );

  final ConnectionState state;
  final String? error;
  final String? info;
  final String? server;
  final DateTime? since;
  final int bytesUp;
  final int bytesDown;
  final int connections;
}

DateTime? _time(Object? unix) =>
    unix is num ? DateTime.fromMillisecondsSinceEpoch(unix.toInt() * 1000) : null;

/// The platform side (Android: MainActivity + AegisVpnService over the
/// Rust core). Results arrive as the core's JSON.
class Client {
  static const _channel = MethodChannel('aegisnet/client');

  Future<Map<String, dynamic>> _call(String method, [Map<String, Object?>? args]) async {
    final raw = await _channel.invokeMethod<String>(method, args);
    final j = jsonDecode(raw ?? '{}') as Map<String, dynamic>;
    if (j['ok'] != true) {
      throw ClientError((j['error'] as String?) ?? 'Something went wrong.');
    }
    return j;
  }

  Future<DeviceInfo> device() async => DeviceInfo.fromJson(await _call('device'));

  Future<DeviceInfo> enroll(String code) async {
    await _call('enroll', {'code': code.trim()});
    return device();
  }

  Future<void> forget() => _call('forget');

  /// Asks Android for VPN permission the first time.
  Future<void> connect() => _call('connect');

  Future<void> disconnect() => _call('disconnect');

  Future<Status> status() async => Status.fromJson(await _call('status'));

  /// An invitation shared to the app from another app, once.
  Future<String?> sharedText() => _channel.invokeMethod<String>('sharedText');
}
