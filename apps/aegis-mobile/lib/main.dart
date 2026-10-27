import 'dart:async';

import 'package:flutter/material.dart' hide ConnectionState;
import 'package:flutter/services.dart';

import 'client.dart';

void main() => runApp(const AegisApp());

class AegisApp extends StatelessWidget {
  const AegisApp({super.key});

  @override
  Widget build(BuildContext context) {
    const seed = Color(0xFF2F6F73);
    return MaterialApp(
      title: 'AegisNet',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(colorSchemeSeed: seed, useMaterial3: true),
      darkTheme: ThemeData(colorSchemeSeed: seed, brightness: Brightness.dark, useMaterial3: true),
      home: const Root(),
    );
  }
}

/// Shows the join screen until the phone is enrolled, then the home screen.
class Root extends StatefulWidget {
  const Root({super.key});

  @override
  State<Root> createState() => _RootState();
}

class _RootState extends State<Root> with WidgetsBindingObserver {
  final client = Client();
  DeviceInfo? device;
  String? shared;

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
    final d = await client.device();
    final text = await client.sharedText();
    if (!mounted) return;
    setState(() {
      device = d;
      if (text != null && text.trim().isNotEmpty) shared = text;
    });
  }

  @override
  Widget build(BuildContext context) {
    final d = device;
    if (d == null) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    if (!d.enrolled) {
      return JoinScreen(
        client: client,
        initial: shared,
        onJoined: (d) => setState(() {
          device = d;
          shared = null;
        }),
      );
    }
    return HomeScreen(
      client: client,
      device: d,
      onForgotten: () => setState(() => device = DeviceInfo(enrolled: false)),
    );
  }
}

class JoinScreen extends StatefulWidget {
  const JoinScreen({super.key, required this.client, required this.onJoined, this.initial});

  final Client client;
  final String? initial;
  final void Function(DeviceInfo) onJoined;

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
      final d = await widget.client.enroll(code.text);
      widget.onJoined(d);
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
      appBar: AppBar(title: const Text('AegisNet')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            Text('Join a server', style: t.headlineSmall),
            const SizedBox(height: 8),
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
  const HomeScreen({super.key, required this.client, required this.device, required this.onForgotten});

  final Client client;
  final DeviceInfo device;
  final VoidCallback onForgotten;

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> with WidgetsBindingObserver {
  Status status = Status();
  Timer? timer;
  bool busy = false;
  String? error;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _poll();
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

  Future<void> _toggle() async {
    setState(() {
      busy = true;
      error = null;
    });
    try {
      if (status.state == ConnectionState.disconnected) {
        await widget.client.connect();
      } else {
        await widget.client.disconnect();
      }
    } on ClientError catch (e) {
      setState(() => error = e.message);
    } finally {
      await Future<void>.delayed(const Duration(milliseconds: 600));
      await _refresh();
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> _forget() async {
    final yes = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        title: const Text('Remove this server?'),
        content: const Text(
          'This phone disconnects and forgets its identity. To connect again you need a new invitation. '
          'Ask your administrator to also remove the device in the console.',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(c, true), child: const Text('Remove')),
        ],
      ),
    );
    if (yes != true) return;
    try {
      await widget.client.forget();
      widget.onForgotten();
    } on ClientError catch (e) {
      setState(() => error = e.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final t = Theme.of(context).textTheme;
    final s = status;
    final (label, color, icon) = switch (s.state) {
      ConnectionState.connected => ('Connected', scheme.primary, Icons.shield),
      ConnectionState.connecting => ('Connecting…', scheme.tertiary, Icons.shield_outlined),
      ConnectionState.disconnected => ('Not connected', scheme.outline, Icons.shield_outlined),
    };
    final on = s.state != ConnectionState.disconnected;
    final server = s.server ?? widget.device.server ?? '';
    final message = error ?? s.error;
    return Scaffold(
      appBar: AppBar(
        title: const Text('AegisNet'),
        actions: [
          PopupMenuButton<String>(
            onSelected: (v) {
              if (v == 'forget') _forget();
            },
            itemBuilder: (_) => const [PopupMenuItem(value: 'forget', child: Text('Remove this server'))],
          ),
        ],
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: [
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
                  ListTile(leading: const Icon(Icons.dns_outlined), title: const Text('Server'), subtitle: Text(server)),
                  ListTile(
                    leading: const Icon(Icons.smartphone),
                    title: const Text('This device'),
                    subtitle: Text(widget.device.name ?? ''),
                  ),
                  if (on) ...[
                    ListTile(
                      leading: const Icon(Icons.swap_vert),
                      title: const Text('Traffic'),
                      subtitle: Text('↑ ${_bytes(s.bytesUp)}   ↓ ${_bytes(s.bytesDown)}'),
                    ),
                    ListTile(
                      leading: const Icon(Icons.lan_outlined),
                      title: const Text('Open connections'),
                      subtitle: Text('${s.connections}'),
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(height: 12),
            Text(
              'While connected, apps on this phone reach the internet through your server. '
              'Local networks (Wi-Fi printers, your router) stay direct.',
              style: t.bodySmall,
            ),
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
