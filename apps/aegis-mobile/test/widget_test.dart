import 'package:aegis_mobile/main.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('an unenrolled phone shows the join screen', (tester) async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(
      const MethodChannel('aegisnet/client'),
      (call) async => switch (call.method) {
        'device' => '{"ok":true,"enrolled":false}',
        'sharedText' => null,
        _ => '{"ok":false,"error":"unexpected"}',
      },
    );
    await tester.pumpWidget(const AegisApp());
    await tester.pumpAndSettle();
    expect(find.text('Join a server'), findsOneWidget);
    expect(find.text('Join'), findsOneWidget);
  });
}
