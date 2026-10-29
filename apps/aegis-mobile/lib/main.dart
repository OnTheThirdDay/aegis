import 'dart:async';

import 'package:flutter/material.dart' hide ConnectionState;
import 'package:flutter/services.dart';

import 'client.dart';

void main() => runApp(const AegisApp());

/// The old Android app (flavor `legacy`, `net.aegis.app`) keeps its name.
final appName = appFlavor == 'legacy' ? 'AegisNet' : 'AegisBorne';

class AegisApp extends StatelessWidget {
  const AegisApp({super.key});

  @override
  Widget build(BuildContext context) {
    const seed = Color(0xFF2F6F73);
    return MaterialApp(
      title: appName,
      debugShowCheckedModeBanner: false,
      theme: ThemeData(colorSchemeSeed: seed, useMaterial3: true),
      darkTheme: ThemeData(colorSchemeSeed: seed, brightness: Brightness.dark, useMaterial3: true),
      home: const Root(),
    );
  }
}

/// Shows the join screen until the phone joined a server, then the home
/// screen for the selected one.
class Root extends StatefulWidget {
  const Root({super.key});

  @override
  State<Root> createState() => _RootState();
}

class _RootState extends State<Root> with WidgetsBindingObserver {
  final client = Client();
  Servers? servers;
  String? shared;
  Migration move = Migration();

  /// A newer app the selected server offers.
  AppUpdate? update;

  /// AegisBorne: servers just taken from the old app, and whether that app
  /// is too old to hand them over.
  int moved = 0;
  bool legacyOutdated = false;
  bool importTried = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _load();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) _load();
  }

  Future<void> _load() async {
    final m = await client.migration();
    var s = await client.servers();
    if (!m.legacy && m.otherInstalled && s.isEmpty && !importTried) {
      importTried = true;
      try {
        final r = await client.importLegacy();
        if (r.count > 0) {
          moved = r.count;
          s = await client.servers();
        }
        legacyOutdated = r.legacy == 'outdated';
      } on ClientError {
        // Join with an invitation instead.
      }
    }
    final text = await client.sharedText();
    if (!mounted) return;
    setState(() {
      move = m;
      servers = s;
      if (s.isEmpty) update = null;
      if (text != null && text.trim().isNotEmpty) shared = text;
    });
    unawaited(_checkUpdate());
  }

  /// Above the join and home screens while both apps are in play.
  Widget? _notice() {
    if (move.legacy) {
      return MoveNotice(
        text: 'AegisNet is now AegisBorne. Move to the new app: your servers come along, '
            'with nothing to join again.',
        action: move.otherInstalled ? 'Open AegisBorne' : 'Move to AegisBorne',
        onPressed: _installBorne,
      );
    }
    if (!move.otherInstalled) return null;
    final none = servers?.isEmpty ?? true;
    if (none) {
      return legacyOutdated
          ? const MoveNotice(
              text: 'To bring your servers over from the AegisNet app, install the AegisNet update '
                  'from your server\'s download page, then open AegisBorne again. '
                  'Or join with a new invitation below.',
            )
          : null;
    }
    return MoveNotice(
      text: moved > 0
          ? 'Moved ${moved == 1 ? 'your server' : 'your $moved servers'} from AegisNet. '
              'You can uninstall the old app now.'
          : 'The old AegisNet app is still installed. AegisBorne replaces it.',
      action: 'Uninstall AegisNet',
      onPressed: () => client.uninstallLegacy(),
    );
  }

  Future<void> _installBorne() async {
    String? message;
    try {
      message = await client.installBorne();
    } on ClientError catch (e) {
      message = e.message;
    }
    if (message != null && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = servers;
    if (s == null) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    if (move.legacy && move.moved) {
      return MovedScreen(onOpen: _installBorne, onUninstall: () => client.uninstallLegacy());
    }
    if (s.isEmpty) {
      return JoinScreen(
        client: client,
        initial: shared,
        notice: _notice(),
        onJoined: (_) {
          shared = null;
          _load();
        },
      );
    }
    return HomeScreen(
      client: client,
      servers: s,
      shared: shared,
      notice: _notice(),
      update: update,
      onSharedTaken: () => shared = null,
      onChanged: _load,
    );
  }

  /// Ask the selected server for a newer app (the core reuses its answer
  /// for a few hours). Not the old app: it moves to AegisBorne instead.
  Future<void> _checkUpdate() async {
    if (move.legacy || (servers?.isEmpty ?? true)) return;
    try {
      final u = await client.checkUpdate();
      if (mounted) setState(() => update = u);
    } on ClientError {
      // Unreachable server: asked again on the next start or resume.
    }
  }
}

class JoinScreen extends StatefulWidget {
  const JoinScreen({
    super.key,
    required this.client,
    required this.onJoined,
    this.initial,
    this.another = false,
    this.notice,
  });

  final Client client;
  final String? initial;

  /// Above everything (moving between the old app and AegisBorne).
  final Widget? notice;
  final void Function(ServerInfo) onJoined;

  /// Joining an additional server (opened from the home screen).
  final bool another;

  @override
  State<JoinScreen> createState() => _JoinScreenState();
}

class _JoinScreenState extends State<JoinScreen> {
  late final code = TextEditingController(text: widget.initial ?? '');
  bool busy = false;
  String? error;

  @override
  void didUpdateWidget(JoinScreen old) {
    super.didUpdateWidget(old);
    if (widget.initial != null && widget.initial != old.initial) code.text = widget.initial!;
  }

  Future<void> _paste() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (data?.text != null) setState(() => code.text = data!.text!.trim());
  }

  Future<void> _join() async {
    setState(() {
      busy = true;
      error = null;
    });
    try {
      final s = await widget.client.enroll(code.text);
      widget.onJoined(s);
    } on ClientError catch (e) {
      setState(() => error = e.message);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: Text(widget.another ? 'Add a server' : appName)),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            if (widget.notice != null) ...[widget.notice!, const SizedBox(height: 16)],
            if (!widget.another) ...[
              Text('Join a server', style: t.headlineSmall),
              const SizedBox(height: 8),
            ],
            Text(
              'Paste the invitation your administrator sent you. It starts with aegis1: '
              'and works once. You can also share it to this app from a chat or mail app.',
              style: t.bodyMedium,
            ),
            const SizedBox(height: 20),
            TextField(
              controller: code,
              minLines: 3,
              maxLines: 6,
              enabled: !busy,
              autocorrect: false,
              enableSuggestions: false,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                labelText: 'Invitation',
                hintText: 'aegis1:…',
              ),
              onChanged: (_) => setState(() {}),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                OutlinedButton.icon(
                  onPressed: busy ? null : _paste,
                  icon: const Icon(Icons.content_paste),
                  label: const Text('Paste'),
                ),
                const Spacer(),
                FilledButton(
                  onPressed: busy || code.text.trim().isEmpty ? null : _join,
                  child: busy
                      ? const SizedBox.square(dimension: 18, child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('Join'),
                ),
              ],
            ),
            if (error != null) ...[
              const SizedBox(height: 16),
              Banner(text: error!, error: true),
            ],
          ],
        ),
      ),
    );
  }
}

class HomeScreen extends StatefulWidget {
  const HomeScreen({
    super.key,
    required this.client,
    required this.servers,
    required this.onChanged,
    required this.onSharedTaken,
    this.shared,
    this.notice,
    this.update,
  });

  final Client client;
  final Servers servers;

  /// A newer app the server offers.
  final AppUpdate? update;

  /// Reload the server list.
  final Future<void> Function() onChanged;

  /// An invitation shared to the app: offered as another server.
  final String? shared;
  final VoidCallback onSharedTaken;

  /// Above everything (moving between the old app and AegisBorne).
  final Widget? notice;

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> with WidgetsBindingObserver {
  Status status = Status();
  Timer? timer;
  bool busy = false;
  String? error;

  /// Downloading an update, until the system installer takes over.
  bool updating = false;

  /// A newer app from the server: offered, never installed unasked.
  Widget _updateCard(AppUpdate u) {
    final scheme = Theme.of(context).colorScheme;
    final (done, total) = (status.updateDone, status.updateTotal);
    return Card(
      color: scheme.primaryContainer,
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              '$appName ${u.version} is available (you have ${u.current}).',
              style: TextStyle(color: scheme.onPrimaryContainer),
            ),
            const SizedBox(height: 10),
            if (updating && done != null && total != null && total > 0)
              LinearProgressIndicator(value: done / total)
            else
              FilledButton(onPressed: updating ? null : _installUpdate, child: const Text('Update')),
          ],
        ),
      ),
    );
  }

  Future<void> _installUpdate() async {
    setState(() {
      updating = true;
      error = null;
    });
    try {
      final message = await widget.client.installUpdate();
      if (message != null && mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
      }
    } on ClientError catch (e) {
      if (mounted) setState(() => error = e.message);
    } finally {
      if (mounted) setState(() => updating = false);
    }
  }

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _poll();
    _takeShared();
  }

  @override
  void didUpdateWidget(HomeScreen old) {
    super.didUpdateWidget(old);
    if (widget.shared != old.shared) _takeShared();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    timer?.cancel();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _poll();
    } else if (state == AppLifecycleState.paused) {
      timer?.cancel();
    }
  }

  void _takeShared() {
    final text = widget.shared;
    if (text == null) return;
    widget.onSharedTaken();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _add(initial: text);
    });
  }

  void _poll() {
    timer?.cancel();
    _refresh();
    timer = Timer.periodic(const Duration(seconds: 1), (_) => _refresh());
  }

  Future<void> _refresh() async {
    try {
      final s = await widget.client.status();
      if (mounted) setState(() => status = s);
    } on ClientError {
      // Keep the last status.
    }
  }

  bool get _on => status.state != ConnectionState.disconnected;

  /// Run [f] with the button disabled, showing its error.
  Future<void> _busy(Future<void> Function() f) async {
    setState(() {
      busy = true;
      error = null;
    });
    try {
      await f();
    } on ClientError catch (e) {
      if (mounted) setState(() => error = e.message);
    } finally {
      await Future<void>.delayed(const Duration(milliseconds: 600));
      await _refresh();
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> _toggle() => _busy(() => _on ? widget.client.disconnect() : widget.client.connect());

  /// Disconnect and wait until the VPN is down (it stops in the background).
  Future<void> _disconnect() async {
    await widget.client.disconnect();
    for (var i = 0; i < 30; i++) {
      final s = await widget.client.status();
      if (s.state == ConnectionState.disconnected) return;
      await Future<void>.delayed(const Duration(milliseconds: 200));
    }
  }

  /// Use another server; one is connected at a time, so a connection moves
  /// over to it.
  Future<void> _switchTo(ServerInfo s) => _busy(() async {
        final reconnect = _on;
        if (reconnect) await _disconnect();
        await widget.client.select(s.id);
        await widget.onChanged();
        if (reconnect) await widget.client.connect();
      });

  Future<void> _add({String? initial}) async {
    final joined = await Navigator.of(context).push<ServerInfo>(
      MaterialPageRoute(
        builder: (c) => JoinScreen(
          client: widget.client,
          initial: initial,
          another: true,
          onJoined: (s) => Navigator.of(c).pop(s),
        ),
      ),
    );
    if (joined == null) return;
    // The new server is selected; move a running connection to it.
    await _busy(() async {
      final reconnect = _on;
      if (reconnect) await _disconnect();
      await widget.onChanged();
      if (reconnect) await widget.client.connect();
    });
  }

  Future<void> _forget(ServerInfo s) async {
    final yes = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        title: Text('Remove ${s.server}?'),
        content: const Text(
          'This phone forgets its identity for this server, and disconnects if it is in use. '
          'To join it again you need a new invitation. '
          'Ask your administrator to also remove the device in the console.',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(c, true), child: const Text('Remove')),
        ],
      ),
    );
    if (yes != true) return;
    await _busy(() async {
      await widget.client.forget(s.id);
      await widget.onChanged();
    });
  }

  Future<void> _pick() async {
    final selected = widget.servers.selected;
    final action = await showModalBottomSheet<(String, ServerInfo?)>(
      context: context,
      showDragHandle: true,
      builder: (c) => SafeArea(
        child: ListView(
          shrinkWrap: true,
          children: [
            for (final s in widget.servers.list)
              ListTile(
                leading: Icon(s.id == selected?.id ? Icons.radio_button_checked : Icons.radio_button_unchecked),
                title: Text(s.server),
                subtitle: Text('as ${s.name}'),
                trailing: IconButton(
                  icon: const Icon(Icons.delete_outline),
                  tooltip: 'Remove',
                  onPressed: () => Navigator.pop(c, ('remove', s)),
                ),
                onTap: () => Navigator.pop(c, ('use', s)),
              ),
            ListTile(
              leading: const Icon(Icons.add),
              title: const Text('Add a server'),
              onTap: () => Navigator.pop(c, ('add', null)),
            ),
          ],
        ),
      ),
    );
    if (action == null || !mounted) return;
    switch (action) {
      case ('use', final ServerInfo s) when s.id != selected?.id:
        await _switchTo(s);
      case ('remove', final ServerInfo s):
        await _forget(s);
      case ('add', _):
        await _add();
    }
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final t = Theme.of(context).textTheme;
    final s = status;
    final current = widget.servers.selected;
    final (label, color, icon) = switch (s.state) {
      ConnectionState.connected => ('Connected', scheme.primary, Icons.shield),
      ConnectionState.connecting => ('Connecting…', scheme.tertiary, Icons.shield_outlined),
      ConnectionState.disconnected => ('Not connected', scheme.outline, Icons.shield_outlined),
    };
    final on = _on;
    final server = (on ? s.server : null) ?? current?.server ?? '';
    final message = error ?? s.error;
    final several = widget.servers.list.length > 1;
    return Scaffold(
      appBar: AppBar(
        title: Text(appName),
        actions: [
          PopupMenuButton<String>(
            enabled: !busy,
            onSelected: (v) {
              if (v == 'add') _add();
              if (v == 'forget' && current != null) _forget(current);
            },
            itemBuilder: (_) => const [
              PopupMenuItem(value: 'add', child: Text('Add a server')),
              PopupMenuItem(value: 'forget', child: Text('Remove this server')),
            ],
          ),
        ],
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            if (widget.notice != null) widget.notice!,
            if (widget.update != null) _updateCard(widget.update!),
            const SizedBox(height: 12),
            Center(
              child: SizedBox.square(
                dimension: 168,
                child: FilledButton(
                  style: FilledButton.styleFrom(
                    shape: const CircleBorder(),
                    backgroundColor: on ? color : scheme.surfaceContainerHighest,
                    foregroundColor: on ? scheme.onPrimary : scheme.onSurfaceVariant,
                  ),
                  onPressed: busy ? null : _toggle,
                  child: Icon(Icons.power_settings_new, size: 72, semanticLabel: on ? 'Disconnect' : 'Connect'),
                ),
              ),
            ),
            const SizedBox(height: 20),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(icon, color: color),
                const SizedBox(width: 8),
                Text(label, style: t.titleLarge?.copyWith(color: color)),
              ],
            ),
            if (s.since != null && s.state == ConnectionState.connected)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text('since ${_clock(s.since!)}', textAlign: TextAlign.center, style: t.bodySmall),
              ),
            const SizedBox(height: 24),
            if (message != null) Banner(text: message, error: true),
            if (s.info != null) Banner(text: s.info!),
            Card(
              child: Column(
                children: [
                  ListTile(
                    leading: const Icon(Icons.dns_outlined),
                    title: Text(several ? 'Server (${widget.servers.list.length} joined)' : 'Server'),
                    subtitle: Text(server),
                    trailing: const Icon(Icons.unfold_more),
                    onTap: busy ? null : _pick,
                  ),
                  ListTile(
                    leading: const Icon(Icons.smartphone),
                    title: const Text('This device'),
                    subtitle: Text(current?.name ?? ''),
                  ),
                  if (on) ...[
                    ListTile(
                      leading: const Icon(Icons.swap_vert),
                      title: const Text('Traffic'),
                      subtitle: Text('↑ ${_bytes(s.bytesUp)}   ↓ ${_bytes(s.bytesDown)}'
                          '${s.transport == null ? '' : s.transport == 'quic' ? '   ·   via QUIC (UDP)' : '   ·   via WebSocket'}'),
                    ),
                    ListTile(
                      leading: const Icon(Icons.lan_outlined),
                      title: const Text('Open connections'),
                      subtitle: Text(s.udpFlows > 0
                          ? '${s.connections}  ·  ${s.udpFlows} UDP'
                          : '${s.connections}'),
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(height: 12),
            Text(
              'While connected, apps on this phone reach the internet through your server. '
              'Local networks (Wi-Fi printers, your router) stay direct. '
              'Tap the server to switch to another one or add one.',
              style: t.bodySmall,
            ),
          ],
        ),
      ),
    );
  }
}

/// Moving between the old app and AegisBorne: what to do, and a button.
class MoveNotice extends StatelessWidget {
  const MoveNotice({super.key, required this.text, this.action, this.onPressed});

  final String text;
  final String? action;
  final VoidCallback? onPressed;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      color: scheme.primaryContainer,
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(text, style: TextStyle(color: scheme.onPrimaryContainer)),
            if (action != null) ...[
              const SizedBox(height: 10),
              FilledButton(onPressed: onPressed, child: Text(action!)),
            ],
          ],
        ),
      ),
    );
  }
}

/// The old app once AegisBorne took its servers.
class MovedScreen extends StatelessWidget {
  const MovedScreen({super.key, required this.onOpen, required this.onUninstall});

  final VoidCallback onOpen;
  final VoidCallback onUninstall;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: Text(appName)),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            Text('Moved to AegisBorne', style: t.headlineSmall),
            const SizedBox(height: 8),
            Text(
              'Your servers are in the AegisBorne app now. Connect from there, and uninstall this app.',
              style: t.bodyMedium,
            ),
            const SizedBox(height: 20),
            FilledButton(onPressed: onOpen, child: const Text('Open AegisBorne')),
            const SizedBox(height: 8),
            OutlinedButton(onPressed: onUninstall, child: const Text('Uninstall AegisNet')),
          ],
        ),
      ),
    );
  }
}

/// A message above the content.
class Banner extends StatelessWidget {
  const Banner({super.key, required this.text, this.error = false});

  final String text;
  final bool error;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      color: error ? scheme.errorContainer : scheme.secondaryContainer,
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Text(text, style: TextStyle(color: error ? scheme.onErrorContainer : scheme.onSecondaryContainer)),
      ),
    );
  }
}

String _bytes(int n) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  var v = n.toDouble();
  var i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return i == 0 ? '$n B' : '${v.toStringAsFixed(v < 10 ? 1 : 0)} ${units[i]}';
}

String _clock(DateTime t) =>
    '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}';
