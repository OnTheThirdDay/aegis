import 'dart:convert';

import 'package:flutter/services.dart';

/// A failed call, with a message for the user.
class ClientError implements Exception {
  ClientError(this.message);
  final String message;
  @override
  String toString() => message;
}

/// A joined server: its address and this phone's name there.
class ServerInfo {
  ServerInfo({required this.id, required this.name, required this.server, this.expiresAt});

  factory ServerInfo.fromJson(Map<String, dynamic> j) => ServerInfo(
        id: j['id'] as String,
        name: j['name'] as String,
        server: j['server'] as String,
        expiresAt: _time(j['certificate_expires_at']),
      );

  final String id;
  final String name;
  final String server;
  final DateTime? expiresAt;
}

/// Every joined server, oldest first, and the one connections use.
class Servers {
  Servers({required this.list, this.selectedId});

  factory Servers.fromJson(Map<String, dynamic> j) => Servers(
        list: [
          for (final s in (j['servers'] as List<dynamic>? ?? const []))
            ServerInfo.fromJson(s as Map<String, dynamic>),
        ],
        selectedId: j['selected'] as String?,
      );

  final List<ServerInfo> list;
  final String? selectedId;

  bool get isEmpty => list.isEmpty;

  ServerInfo? get selected {
    for (final s in list) {
      if (s.id == selectedId) return s;
    }
    return list.isEmpty ? null : list.first;
  }
}

enum ConnectionState { disconnected, connecting, connected }

/// Connection state and counters.
class Status {
  Status({
    this.state = ConnectionState.disconnected,
    this.error,
    this.info,
    this.serverId,
    this.server,
    this.since,
    this.bytesUp = 0,
    this.bytesDown = 0,
    this.connections = 0,
    this.udpFlows = 0,
  });

  factory Status.fromJson(Map<String, dynamic> j) => Status(
        state: switch (j['state']) {
          'connected' => ConnectionState.connected,
          'connecting' => ConnectionState.connecting,
          _ => ConnectionState.disconnected,
        },
        error: j['error'] as String?,
        info: j['info'] as String?,
        serverId: j['server_id'] as String?,
        server: j['server'] as String?,
        since: _time(j['connected_since']),
        bytesUp: (j['bytes_up'] as num?)?.toInt() ?? 0,
        bytesDown: (j['bytes_down'] as num?)?.toInt() ?? 0,
        connections: (j['connections'] as num?)?.toInt() ?? 0,
        udpFlows: (j['udp_flows'] as num?)?.toInt() ?? 0,
      );

  final ConnectionState state;
  final String? error;
  final String? info;

  /// The server of the current (or last) connection.
  final String? serverId;
  final String? server;
  final DateTime? since;
  final int bytesUp;
  final int bytesDown;
  final int connections;

  /// Open UDP flows (calls, games, QUIC).
  final int udpFlows;
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

  Future<Servers> servers() async => Servers.fromJson(await _call('servers'));

  /// Joins another server and selects it.
  Future<ServerInfo> enroll(String code) async =>
      ServerInfo.fromJson(await _call('enroll', {'code': code.trim()}));

  /// The server the next connection uses.
  Future<void> select(String id) => _call('select', {'id': id});

  /// Removes a server, disconnecting first if it is the connected one.
  Future<void> forget(String id) => _call('forget', {'id': id});

  /// Connects to the selected server; asks Android for VPN permission the
  /// first time.
  Future<void> connect() => _call('connect');

  Future<void> disconnect() => _call('disconnect');

  Future<Status> status() async => Status.fromJson(await _call('status'));

  /// An invitation shared to the app from another app, once.
  Future<String?> sharedText() => _channel.invokeMethod<String>('sharedText');
}
