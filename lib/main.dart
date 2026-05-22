import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const MyApp());
}

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

  static const MethodChannel platform = MethodChannel(
    'com.paadevelopments.attestation_app/security',
  );

  /*
   * =========================================================
   * BACKEND URL
   * =========================================================
   */

  static const String backendBaseUrl = 'http://YOUR_SERVER_IP:3000';
  bool _isLoading = false;
  String _status = 'System integrity not yet verified';
  String? _nonce;
  Map<String, dynamic>? _serverResult;
  Map<dynamic, dynamic>? _localReport;

  /*
   * =========================================================
   * STEP 1
   * REQUEST NONCE FROM AMS BACKEND
   * =========================================================
   */

  Future<void> _requestNonce() async {
    setState(() {
      _isLoading = true;
      _status = 'Requesting attestation nonce...';
    });
    try {
      final response =
      await http.get(Uri.parse('$backendBaseUrl/api/attestation/nonce'));
      if (response.statusCode != 200) {
        throw Exception('Failed to retrieve nonce');
      }
      final body = jsonDecode(response.body);
      final nonce = body['nonce'];
      if (nonce == null) {
        throw Exception('Server returned invalid nonce');
      }
      setState(() {
        _nonce = nonce;
        _status = 'Nonce acquired successfully';
      });
    } catch (e) {
      setState(() {
        _status = 'Nonce request failed: $e';
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  /*
   * =========================================================
   * STEP 2
   * GENERATE ATTESTATION + SEND TO BACKEND
   * =========================================================
   */

  Future<void> _runFullAttestation() async {
    if (_nonce == null) {
      setState(() {
        _status = 'Request nonce first';
      });
      return;
    }
    setState(() {
      _isLoading = true;
      _status = 'Generating hardware attestation...';
    });
    try {
      /*
       * =====================================================
       * GET LOCAL DEVICE REPORT
       * =====================================================
       */
      final Map<dynamic, dynamic> report =
      await platform.invokeMethod('getSecurityReport',{'nonce': _nonce});
      setState(() {
        _localReport = report;
        _status = 'Sending attestation to AMS backend...';
      });
      /*
       * =====================================================
       * SEND TO BACKEND
       * =====================================================
       */
      final response = await http.post(
        Uri.parse('$backendBaseUrl/api/attestation/verify'),
        headers: {
          'Content-Type':
          'application/json',
        },
        body: jsonEncode({
          'nonce': _nonce,
          'manufacturer': report['manufacturer'],
          'brand': report['brand'],
          'model': report['model'],
          'device': report['device'],
          'product': report['product'],
          'sdkInt': report['sdkInt'],
          'isRooted': report['isRooted'],
          'isHookDetected': report['isHookDetected'],
          'isSELinuxEnforced': report['isSELinuxEnforced'],
          'verifiedBootState': report['verifiedBootState'],
          'isBootloaderLocked': report['isBootloaderLocked'],
          'attestationSecurityLevel': report['attestationSecurityLevel'],
          'keymasterSecurityLevel': report['keymasterSecurityLevel'],
          'certificateChain': report['certificateChain'],
        }),
      );
      if (response.statusCode != 200) {
        throw Exception('Backend validation failed');
      }
      final result = jsonDecode(response.body);
      setState(() {
        _serverResult = result;
        final bool passed = result['success'] == true;
        if (passed) {
          _status = '✅ PCI MPoC attestation passed';
        } else {
          _status = '❌ PCI MPoC attestation failed';
        }
      });
    } on PlatformException catch (e) {
      setState(() {
        _status = 'Platform error: ${e.message}';
      });
    } catch (e) {
      setState(() {
        _status = 'Attestation failed: $e';
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  /*
   * =========================================================
   * STATUS COLOR
   * =========================================================
   */

  Color _statusColor() {
    if (_status.contains('passed')) {
      return Colors.green;
    }
    if (_status.contains('failed')) {
      return Colors.red;
    }
    return Colors.orange;
  }

  /*
   * =========================================================
   * BUILD
   * =========================================================
   */

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text(
          'PCI MPoC Security Check',
        ),
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment:
            CrossAxisAlignment.stretch,
            children: [
              /*
               * =================================================
               * STATUS CARD
               * =================================================
               */
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    children: [
                      Icon(
                        Icons.security,
                        size: 56,
                        color: _statusColor(),
                      ),
                      const SizedBox(height: 16),
                      Text(
                        _status,
                        textAlign: TextAlign.center,
                        style: TextStyle(
                          fontSize: 18,
                          fontWeight:
                          FontWeight.bold,
                          color: _statusColor(),
                        ),
                      ),
                      const SizedBox(height: 24),
                      if (_isLoading)
                        const CircularProgressIndicator()
                      else ...[
                        FilledButton.icon(
                          onPressed: _requestNonce,
                          icon: const Icon(Icons.vpn_key),
                          label: const Text(
                            '1. Request Nonce',
                          ),
                        ),
                        const SizedBox(height: 12),
                        FilledButton.icon(
                          onPressed: _runFullAttestation,
                          icon: const Icon(Icons.verified_user),
                          label: const Text(
                            '2. Run Attestation',
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              /*
               * =================================================
               * NONCE
               * =================================================
               */
              if (_nonce != null)
                _buildSectionCard(
                  title: 'Server Nonce',
                  children: [
                    SelectableText(
                      _nonce!,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                      ),
                    ),
                  ],
                ),
              /*
               * =================================================
               * LOCAL DEVICE REPORT
               * =================================================
               */
              if (_localReport != null)
                _buildSectionCard(
                  title: 'Device Information',
                  children: [
                    _buildRow(
                      'Manufacturer',
                      '${_localReport!['manufacturer']}',
                    ),
                    _buildRow(
                      'Brand',
                      '${_localReport!['brand']}',
                    ),
                    _buildRow(
                      'Model',
                      '${_localReport!['model']}',
                    ),
                    _buildRow(
                      'Android SDK',
                      '${_localReport!['sdkInt']}',
                    ),
                  ],
                ),
              /*
               * =================================================
               * SECURITY CHECKS
               * =================================================
               */
              if (_localReport != null)
                _buildSectionCard(
                  title: 'Security Checks',
                  children: [
                    _buildBooleanRow(
                      'Root Detected',
                      _localReport!['isRooted'],
                    ),
                    _buildBooleanRow(
                      'Hook Framework',
                      _localReport!['isHookDetected'],
                    ),
                    _buildBooleanRow(
                      'SELinux Enforced',
                      _localReport!['isSELinuxEnforced'],
                      invert: false,
                    ),

                    _buildBooleanRow(
                      'Bootloader Locked',
                      _localReport!['isBootloaderLocked'],
                      invert: false,
                    ),
                  ],
                ),
              /*
               * =================================================
               * VERIFIED BOOT
               * =================================================
               */

              if (_localReport != null)
                _buildSectionCard(
                  title: 'Verified Boot',
                  children: [
                    _buildRow(
                      'Verified Boot State',
                      '${_localReport!['verifiedBootState']}',
                    ),
                    _buildRow(
                      'Attestation Security',
                      '${_localReport!['attestationSecurityLevel']}',
                    ),
                    _buildRow(
                      'Keymaster Security',
                      '${_localReport!['keymasterSecurityLevel']}',
                    ),
                  ],
                ),
              /*
               * =================================================
               * CERTIFICATES
               * =================================================
               */
              if (_localReport != null)
                _buildSectionCard(
                  title: 'Attestation Certificates',
                  children: [
                    _buildRow(
                      'Certificate Count',
                      '${(_localReport!['certificateChain'] as List?)?.length ?? 0}',
                    ),
                    _buildRow(
                      'Hardware Attestation',
                      ((_localReport!['certificateChain'] as List?)?.isNotEmpty ?? false) ? 'AVAILABLE' : 'NOT AVAILABLE',
                    ),
                  ],
                ),
              /*
               * =================================================
               * SERVER VALIDATION
               * =================================================
               */
              if (_serverResult != null)
                _buildSectionCard(
                  title: 'AMS Backend Validation',
                  children: [
                    _buildBooleanRow(
                      'Validation Success',
                      _serverResult!['success'],
                      invert: false,
                    ),
                    _buildBooleanRow(
                      'Nonce Valid',
                      _serverResult!['nonceValid'],
                      invert: false,
                    ),
                    _buildBooleanRow(
                      'Certificate Chain Trusted',
                      _serverResult!['certificateChainTrusted'],
                      invert: false,
                    ),
                    _buildBooleanRow(
                      'Rollback Resistant',
                      _serverResult!['rollbackResistant'],
                      invert: false,
                    ),
                    _buildBooleanRow(
                      'Hardware Backed',
                      _serverResult!['hardwareBacked'],
                      invert: false,
                    ),
                    _buildBooleanRow(
                      'Bootloader Locked',
                      _serverResult!['bootloaderLocked'],
                      invert: false,
                    ),
                    _buildRow(
                      'Risk Level',
                      '${_serverResult!['riskLevel']}',
                    ),
                  ],
                ),
            ],
          ),
        ),
      ),
    );
  }

  /*
   * =========================================================
   * SECTION CARD
   * =========================================================
   */

  Widget _buildSectionCard({
    required String title,
    required List<Widget> children,
  }) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment:
            CrossAxisAlignment.start,
            children: [
              Text(
                title,
                style: const TextStyle(
                  fontSize: 18,
                  fontWeight:
                  FontWeight.bold,
                ),
              ),
              const SizedBox(height: 16),
              ...children,
            ],
          ),
        ),
      ),
    );
  }

  /*
   * =========================================================
   * NORMAL ROW
   * =========================================================
   */

  Widget _buildRow(String label, String value,) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          Expanded(
            child: Text(
              label,
              style: const TextStyle(
                fontWeight:
                FontWeight.w600,
              ),
            ),
          ),
          Flexible(
            child: Text(
              value,
              textAlign: TextAlign.end,
            ),
          ),
        ],
      ),
    );
  }

  /*
   * =========================================================
   * BOOLEAN ROW
   * =========================================================
   */

  Widget _buildBooleanRow(String label, bool? value, {bool invert = true}) {
    final bool safe = invert ? !(value ?? true) : (value ?? false);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          Expanded(
            child: Text(
              label,
              style: const TextStyle(
                fontWeight:
                FontWeight.w600,
              ),
            ),
          ),
          Icon(
            safe ? Icons.check_circle : Icons.cancel,
            color: safe ? Colors.green : Colors.red,
          ),
        ],
      ),
    );
  }
}