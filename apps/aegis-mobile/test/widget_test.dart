import 'package:aegis_mobile/main.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart' show SizedBox;
import 'package:flutter_test/flutter_test.dart';

void mockCore(String servers) {
  TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(
    const MethodChannel('aegisnet/client'),
    (call) async => switch (call.method) {
      'servers' => servers,
      'status' => '{"ok":true,"state":"disconnected"}',
      'sharedText' => null,
      _ => '{"ok":false,"error":"unexpected"}',
    },
  );
}

void main() {
  testWidgets('a phone without servers shows the join screen', (tester) async {
    mockCore('{"ok":true,"servers":[],"selected":null}');
    await tester.pumpWidget(const AegisApp());
    await tester.pumpAndSettle();
    expect(find.text('Join a server'), findsOneWidget);
    expect(find.text('Join'), findsOneWidget);
  });

  testWidgets('joined servers are listed and the selected one is shown', (tester) async {
    mockCore('{"ok":true,"selected":"bbbbbbbbbbbbbbbb","servers":['
        '{"id":"aaaaaaaaaaaaaaaa","name":"phone","server":"home.example.test"},'
        '{"id":"bbbbbbbbbbbbbbbb","name":"pixel","server":"work.example.test"}]}');
    await tester.pumpWidget(const AegisApp());
    await tester.pump();
    await tester.pump();
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
}
