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
    this.transport,
    this.updateDone,
    this.updateTotal,
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
        transport: j['transport'] as String?,
        updateDone: (j['update_done'] as num?)?.toInt(),
        updateTotal: (j['update_total'] as num?)?.toInt(),
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

  /// What carries the tunnel: `quic` (direct UDP) or `websocket`.
  final String? transport;

  /// An app update downloading: bytes done and total.
  final int? updateDone;
  final int? updateTotal;
}

/// On-demand diagnostics: a recording of what the connection does while
/// the user reproduces a problem, for the administrator (ADR-0008).
class Diagnostics {
  Diagnostics({this.state = 'off', this.remaining, this.events = 0, this.sending = false, this.sent, this.message, this.file});

  factory Diagnostics.fromJson(Map<String, dynamic> j) {
    final r = j['result'] as Map<String, dynamic>?;
    return Diagnostics(
      state: (j['state'] as String?) ?? 'off',
      remaining: (j['remaining_seconds'] as num?)?.toInt(),
      events: (j['events'] as num?)?.toInt() ?? 0,
      sending: j['sending'] == true,
      sent: r?['sent'] as bool?,
      message: r?['message'] as String?,
      file: r?['file'] as String?,
    );
  }

  /// `off`, `recording`, or `stopped` (recorded, kept for an hour).
  final String state;

  /// Seconds left while recording.
  final int? remaining;
  final int events;
  final bool sending;

  /// The last send: whether the report arrived, and what to tell the user.
  final bool? sent;
  final String? message;

  /// A report saved because it couldn't be sent (iOS), to share.
  final String? file;
}

/// A newer version of the app that the server offers, signed by the
/// release workflow (ADR-0017), and the version installed.
class AppUpdate {
  AppUpdate(this.version, this.current);
  final String version;
  final String current;
}

/// Moving from the old Android app (AegisNet, `net.aegis.app`) to AegisBorne
/// (android/.../Migration.kt).
class Migration {
  Migration({this.legacy = false, this.moved = false, this.otherInstalled = false});

  factory Migration.fromJson(Map<String, dynamic> j) => Migration(
        legacy: j['legacy'] == true,
        moved: j['moved'] == true,
        otherInstalled: j['other_installed'] == true,
      );

  /// This is the old app.
  final bool legacy;

  /// The old app: AegisBorne took its servers.
  final bool moved;

  /// The other app (AegisBorne in the old app, and the reverse) is installed.
  final bool otherInstalled;
}

/// What taking the old app's servers found: how many it added, and the old
/// app's state (`absent`, `outdated`: too old to hand them over,
/// `untrusted`: not signed by us, `done`: taken before, `ok`).
typedef Imported = ({int count, String legacy});

DateTime? _time(Object? unix) =>
    unix is num ? DateTime.fromMillisecondsSinceEpoch(unix.toInt() * 1000) : null;

/// The platform side (Android: MainActivity + AegisVpnService over the
/// Rust core). Results arrive as the core's JSON.
class Client {
  static const _channel = MethodChannel('aegisborne/client');

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

  /// Where the move to AegisBorne stands (nothing to move on iOS, or when
  /// the platform can't tell).
  Future<Migration> migration() async {
    try {
      return Migration.fromJson(await _call('migration'));
    } on MissingPluginException {
      return Migration();
    } on ClientError {
      return Migration();
    }
  }

  /// AegisBorne: take the old app's servers, once.
  Future<Imported> importLegacy() async {
    final j = await _call('importLegacy');
    return (count: (j['imported'] as num?)?.toInt() ?? 0, legacy: (j['legacy'] as String?) ?? 'absent');
  }

  /// The old app: install the AegisBorne it carries, or open it. Returns a
  /// message when the user has something to do first.
  Future<String?> installBorne() async => (await _call('installBorne'))['message'] as String?;

  /// A newer app the selected server offers (checked every few hours), or
  /// null. On iOS it installs through the system, like the first install.
  Future<AppUpdate?> checkUpdate() async {
    try {
      final j = await _call('checkUpdate');
      final v = j['version'] as String?;
      return v == null ? null : AppUpdate(v, (j['current'] as String?) ?? '');
    } on MissingPluginException {
      return null;
    }
  }

  /// Download the offered update and hand it to the system installer,
  /// which asks the user (iOS: opens the install link; iOS downloads it).
  /// Returns a message when the user has something to do first.
  Future<String?> installUpdate() async => (await _call('installUpdate'))['message'] as String?;

  Future<Diagnostics> diagnostics() async => Diagnostics.fromJson(await _call('diagStatus'));

  /// Record for [minutes]. On iOS, while the VPN is off, this connects and
  /// records from the start of the connection.
  Future<void> startDiagnostics(int minutes) => _call('diagStart', {'minutes': minutes});

  /// Stop recording; with [send], send the report. Returns the outcome
  /// (null when not sending).
  Future<({bool sent, String message})?> stopDiagnostics({required bool send}) async {
    final j = await _call('diagStop', {'send': send});
    final message = j['message'] as String?;
    return message == null ? null : (sent: j['sent'] == true, message: message);
  }

  /// Send the recorded report to the server.
  Future<({bool sent, String message})> sendDiagnostics() async {
    final j = await _call('diagSend');
    return (sent: j['sent'] == true, message: (j['message'] as String?) ?? '');
  }

  Future<void> discardDiagnostics() => _call('diagDiscard');

  /// Save the report to a file and offer it to another app (chat, mail),
  /// for when the server can't be reached; the administrator imports it.
  Future<void> shareDiagnostics() => _call('diagShare');

  /// Ask Android to uninstall the old app (the user confirms).
  Future<void> uninstallLegacy() => _call('uninstallLegacy');
}
