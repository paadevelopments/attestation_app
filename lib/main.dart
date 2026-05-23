import 'dart:convert';
import 'dart:developer';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const MyApp());
}

/*
 * =========================================================
 * ATTESTATION API LAYER
 * =========================================================
 */
class AttestationApi {
  final String baseUrl;

  AttestationApi(this.baseUrl);

  Future<String> requestNonce() async {
    // Corrected to matching GET request
    final response = await http.get(
      Uri.parse('$baseUrl/nonce'),
    );

    if (response.statusCode != 200) {
      throw Exception('Failed to fetch nonce');
    }

    final data = jsonDecode(response.body);
    final nonce = data['nonce'];

    if (nonce == null) {
      throw Exception('Invalid nonce from server');
    }

    return nonce;
  }

  Future<Map<String, dynamic>> submitAttestation({
    required String nonce,
    required Map<dynamic, dynamic> report,
  }) async {
    // Transform the list of integer byte arrays into Base64 strings for serialization compatibility
    List<String> base64Chain = [];
    if (report['certificateChain'] != null) {
      for (var certBytes in report['certificateChain']) {
        base64Chain.add(base64Encode(List<int>.from(certBytes)));
      }
    }

    final response = await http.post(
      Uri.parse('$baseUrl/attest'), // Pointing to unified endpoint route
      headers: {
        'Content-Type': 'application/json',
      },
      body: jsonEncode({
        'nonce': nonce,

        // Device identity
        'manufacturer': report['manufacturer'],
        'brand': report['brand'],
        'model': report['model'],
        'device': report['device'],
        'product': report['product'],
        'sdkInt': report['sdkInt'],

        // Security signals
        'isRooted': report['isRooted'],
        'isHookDetected': report['isHookDetected'],

        'verifiedBootState': report['verifiedBootState'],
        'isBootloaderLocked': report['isBootloaderLocked'],
        'attestationSecurityLevel': report['attestationSecurityLevel'],
        'keymasterSecurityLevel': report['keymasterSecurityLevel'],

        // Normalized cryptographic proof chain sent as Base64 format
        'certificateChain': base64Chain,
      }),
    );

    if (response.statusCode != 200) {
      throw Exception('Attestation rejected by backend: ${response.body}');
    }

    return jsonDecode(response.body);
  }
}

/*
 * =========================================================
 * UI APP
 * =========================================================
 */
class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'PCI MPoC Attestation',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: Colors.deepPurple,
      ),
      home: const MyHomePage(),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key});

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  static const MethodChannel platform =
  MethodChannel('com.paadevelopments.attestation_app/security');

  final AttestationApi api = AttestationApi('http://10.128.45.50:8080');

  String? _nonce;
  bool _loading = false;
  String _status = 'System integrity not verified';

  Map<dynamic, dynamic>? _localReport;
  Map<String, dynamic>? _serverResult;

  Future<void> _requestNonce() async {
    setState(() {
      _loading = true;
      _status = 'Requesting nonce...';
    });

    try {
      final nonce = await api.requestNonce();
      setState(() {
        _nonce = nonce;
        _status = 'Nonce acquired';
      });
    } catch (e) {
      setState(() {
        _status = 'Nonce error: $e';
      });
    } finally {
      setState(() {
        _loading = false;
      });
    }
  }

  Future<void> _runAttestation() async {
    if (_nonce == null) {
      setState(() => _status = 'Request nonce first');
      return;
    }

    setState(() {
      _loading = true;
      _status = 'Generating attestation...';
    });

    try {
      final report = await platform.invokeMethod(
        'getSecurityReport',
        {'nonce': _nonce},
      );

      log(jsonEncode(report));

      setState(() {
        _localReport = report;
        _status = 'Sending to backend...';
      });

      final result = await api.submitAttestation(
        nonce: _nonce!,
        report: report,
      );

      setState(() {
        _serverResult = result;
        _status = result['success'] == true ? '✅ MPoC Approved' : '❌ MPoC Rejected';
      });
    } catch (e) {
      setState(() {
        _status = 'Attestation failed: $e';
      });
    } finally {
      setState(() {
        _loading = false;
      });
    }
  }

  Color _statusColor() {
    if (_status.contains('Approved')) return Colors.green;
    if (_status.contains('Rejected')) return Colors.red;
    return Colors.orange;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('PCI MPoC Security Check'),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  children: [
                    Icon(Icons.security, size: 50, color: _statusColor()),
                    const SizedBox(height: 12),
                    Text(
                      _status,
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                        color: _statusColor(),
                      ),
                    ),
                    const SizedBox(height: 16),
                    if (_loading)
                      const CircularProgressIndicator()
                    else ...[
                      ElevatedButton(
                        onPressed: _requestNonce,
                        child: const Text('1. Request Nonce'),
                      ),
                      const SizedBox(height: 10),
                      ElevatedButton(
                        onPressed: _runAttestation,
                        child: const Text('2. Run Attestation'),
                      ),
                    ]
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),
            if (_nonce != null) _infoCard('Nonce', _nonce!),
            if (_localReport != null) _infoCard('Device', _localReport.toString()),
            if (_serverResult != null) _infoCard('Backend Result', _serverResult.toString()),
          ],
        ),
      ),
    );
  }

  Widget _infoCard(String title, String value) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: const TextStyle(fontWeight: FontWeight.bold)),
            const SizedBox(height: 8),
            SelectableText(value),
          ],
        ),
      ),
    );
  }
}