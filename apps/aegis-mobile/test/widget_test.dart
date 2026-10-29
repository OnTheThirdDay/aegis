import 'package:aegis_mobile/main.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart' show SizedBox;
import 'package:flutter_test/flutter_test.dart';

/// Answers the platform channel like the Android side would. [servers] is
/// what the core lists, [migration] where the move from AegisNet stands, and
/// [afterImport] the list once AegisBorne took the old app's servers.
List<String> mockCore(
  String servers, {
  String migration = '{"ok":true,"legacy":false,"moved":false,"other_installed":false}',
  String? afterImport,
  String importResult = '{"ok":true,"imported":0,"legacy":"absent"}',
}) {
  final calls = <String>[];
  var list = servers;
  TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(
    const MethodChannel('aegisborne/client'),
    (call) async {
      calls.add(call.method);
      switch (call.method) {
        case 'servers':
          return list;
        case 'status':
          return '{"ok":true,"state":"disconnected"}';
        case 'sharedText':
          return null;
        case 'migration':
          return migration;
        case 'importLegacy':
          if (afterImport != null) list = afterImport;
          return importResult;
        case 'uninstallLegacy':
          return '{"ok":true}';
      }
      return '{"ok":false,"error":"unexpected"}';
    },
  );
  return calls;
}

const twoServers = '{"ok":true,"selected":"bbbbbbbbbbbbbbbb","servers":['
    '{"id":"aaaaaaaaaaaaaaaa","name":"phone","server":"home.example.test"},'
    '{"id":"bbbbbbbbbbbbbbbb","name":"pixel","server":"work.example.test"}]}';
const noServers = '{"ok":true,"servers":[],"selected":null}';

void main() {
  testWidgets('a phone without servers shows the join screen', (tester) async {
    mockCore(noServers);
    await tester.pumpWidget(const AegisApp());
    await tester.pumpAndSettle();
    expect(find.text('Join a server'), findsOneWidget);
    expect(find.text('Join'), findsOneWidget);
    expect(find.textContaining('AegisNet'), findsNothing);
  });

  testWidgets('joined servers are listed and the selected one is shown', (tester) async {
    mockCore(twoServers);
    await tester.pumpWidget(const AegisApp());
    await tester.pumpAndSettle();
    expect(find.text('Server (2 joined)'), findsOneWidget);
    expect(find.text('work.example.test'), findsOneWidget);
    expect(find.text('pixel'), findsOneWidget);
    await tester.tap(find.text('Server (2 joined)'));
    await tester.pumpAndSettle();
    expect(find.text('home.example.test'), findsOneWidget);
    expect(find.text('as phone'), findsOneWidget);
    expect(find.text('Add a server'), findsOneWidget);
    // Dispose the home screen and its status timer.
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('AegisBorne takes the old app\'s servers and offers to remove it', (tester) async {
    final calls = mockCore(
      noServers,
      migration: '{"ok":true,"legacy":false,"moved":false,"other_installed":true}',
      afterImport: twoServers,
      importResult: '{"ok":true,"imported":2,"legacy":"ok"}',
    );
    await tester.pumpWidget(const AegisApp());
    await tester.pumpAndSettle();
    expect(calls.where((c) => c == 'importLegacy'), hasLength(1));
    expect(find.text('Server (2 joined)'), findsOneWidget);
    expect(find.textContaining('Moved your 2 servers from AegisNet'), findsOneWidget);
    await tester.tap(find.text('Uninstall AegisNet'));
    await tester.pump();
    expect(calls, contains('uninstallLegacy'));
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('an old app too old to hand over its servers is explained', (tester) async {
    mockCore(
      noServers,
      migration: '{"ok":true,"legacy":false,"moved":false,"other_installed":true}',
      importResult: '{"ok":true,"imported":0,"legacy":"outdated"}',
    );
    await tester.pumpWidget(const AegisApp());
    await tester.pumpAndSettle();
    expect(find.textContaining('install the AegisNet update'), findsOneWidget);
    expect(find.text('Join a server'), findsOneWidget);
  });

  testWidgets('servers are taken only while AegisBorne has none', (tester) async {
    final calls = mockCore(
      twoServers,
      migration: '{"ok":true,"legacy":false,"moved":false,"other_installed":true}',
    );
    await tester.pumpWidget(const AegisApp());
    await tester.pumpAndSettle();
    expect(calls, isNot(contains('importLegacy')));
    expect(find.textContaining('still installed'), findsOneWidget);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('the old app points to AegisBorne, then says it moved', (tester) async {
    mockCore(twoServers, migration: '{"ok":true,"legacy":true,"moved":false,"other_installed":false}');
    await tester.pumpWidget(const AegisApp());
    await tester.pumpAndSettle();
    expect(find.text('Move to AegisBorne'), findsOneWidget);
    await tester.pumpWidget(const SizedBox());

    mockCore(twoServers, migration: '{"ok":true,"legacy":true,"moved":true,"other_installed":true}');
    await tester.pumpWidget(const AegisApp());
    await tester.pumpAndSettle();
    expect(find.text('Moved to AegisBorne'), findsOneWidget);
    expect(find.text('Open AegisBorne'), findsOneWidget);
  });
}
