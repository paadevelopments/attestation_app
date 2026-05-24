import "dart:convert";
import "package:http/http.dart" as http;

class AttestationApi {
  final String baseUrl;

  AttestationApi(this.baseUrl);

  Future<String> requestNonce() async {
    final response = await http.get(Uri.parse("$baseUrl/nonce"));

    if (response.statusCode != 200) {
      throw Exception("Failed to fetch nonce");
    }

    final data = jsonDecode(response.body);
    final nonce = data["nonce"];

    if (nonce == null) {
      throw Exception("Invalid nonce from server");
    }

    return nonce;
  }

  Future<Map<String, dynamic>> submitAttestation({
    required String nonce,
    required Map<dynamic, dynamic> report,
  }) async {
    List<dynamic> nativeChain = report["certificateChain"] ?? [];
    List<String> base64Chain = nativeChain
        .map((cert) => cert.toString())
        .toList();

    final response = await http.post(
      Uri.parse("$baseUrl/attest"),
      headers: {"Content-Type": "application/json"},
      body: jsonEncode({
        "nonce": nonce,
        "packageName": report["packageName"],

        // Device identity
        "manufacturer": report["manufacturer"],
        "brand": report["brand"],
        "model": report["model"],
        "device": report["device"],
        "product": report["product"],
        "sdkInt": report["sdkInt"],

        // Security signals
        "isRooted": report["isRooted"],
        "isHookDetected": report["isHookDetected"],

        "verifiedBootState": report["verifiedBootState"],
        "isBootloaderLocked": report["isBootloaderLocked"],
        "attestationSecurityLevel": report["attestationSecurityLevel"],
        "keymasterSecurityLevel": report["keymasterSecurityLevel"],

        // Clean, structured cryptographic proof chain forwarded directly to your multi-root backend
        "certificateChain": base64Chain,
      }),
    );

    if (response.statusCode != 200) {
      throw Exception("Attestation rejected by backend: ${response.body}");
    }

    return jsonDecode(response.body);
  }
}
