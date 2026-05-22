package com.paadevelopments.attestation_app;

import androidx.annotation.NonNull;

import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Debug;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.flutter.embedding.android.FlutterActivity;
import io.flutter.embedding.engine.FlutterEngine;
import io.flutter.plugin.common.MethodChannel;

public class MainActivity extends FlutterActivity {

    private static final String TAG = "MPOC_ATTESTATION";
    private static final String CHANNEL = "com.paadevelopments.attestation_app/security";
    private static final String KEY_ALIAS = "mpoc_attestation_key";

    private static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
    private static final int KM_TAG_ROOT_OF_TRUST = 704;

    @Override
    public void configureFlutterEngine(@NonNull FlutterEngine flutterEngine) {
        super.configureFlutterEngine(flutterEngine);
        new MethodChannel(flutterEngine.getDartExecutor().getBinaryMessenger(), CHANNEL)
                .setMethodCallHandler((call, result) -> {
                    switch (call.method) {
                        case "getSecurityReport":
                            try {
                                String nonce = call.argument("nonce");
                                if (nonce == null || nonce.trim().isEmpty()) {
                                    result.error("INVALID_NONCE", "Nonce missing", null);
                                    return;
                                }
                                result.success(buildSecurityReport(nonce));
                            } catch (Exception e) {
                                result.error("ATTESTATION_ERROR", e.getMessage(), null);
                            }
                            break;
                        case "checkBootloaderStatus":
                            try {
                                List<byte[]> chain = call.argument("certificateChain");
                                result.success(isBootloaderLocked(chain));
                            } catch (Exception e) {
                                result.error("BOOTLOADER_ERROR", e.getMessage(), null);
                            }
                            break;
                        case "getVerifiedBootState":
                            try {
                                List<byte[]> chain = call.argument("certificateChain");
                                result.success(getVerifiedBootState(chain));
                            } catch (Exception e) {
                                result.error("BOOTSTATE_ERROR", e.getMessage(), null);
                            }
                            break;
                        default:
                            result.notImplemented();
                    }
                });
    }

    private Map<String, Object> buildSecurityReport(String nonce) {
        Map<String, Object> report = new HashMap<>();
        report.put("manufacturer", Build.MANUFACTURER);
        report.put("brand", Build.BRAND);
        report.put("model", Build.MODEL);
        report.put("device", Build.DEVICE);
        report.put("product", Build.PRODUCT);
        report.put("sdkInt", Build.VERSION.SDK_INT);
        report.put("androidVersion", Build.VERSION.RELEASE);
        report.put("isRooted", isDeviceRooted());
        report.put("isHookDetected", isHookingFrameworkDetected());
        report.put("isDebuggerAttached", Debug.isDebuggerConnected());
        report.put("isEmulator", isEmulator());
        byte[][] chain = getHardwareAttestationChain(nonce);
        if (chain != null) {
            List<byte[]> certList = new ArrayList<>();
            Collections.addAll(certList, chain);
            report.put("certificateChain", certList);
            report.put("isBootloaderLocked", isBootloaderLocked(certList));
            report.put("verifiedBootState", getVerifiedBootState(certList));
            report.put("attestationSecurityLevel", getAttestationSecurityLevel(certList));
            report.put("keymasterSecurityLevel", getKeymasterSecurityLevel(certList));
            report.put("hardwareBacked", isHardwareBackedKeyStore());
            report.put("strongBoxSupported", isStrongBoxSupported());
        } else {
            report.put("certificateChain", null);
            report.put("isBootloaderLocked", false);
            report.put("verifiedBootState", "UNKNOWN");
            report.put("attestationSecurityLevel", "UNKNOWN");
            report.put("keymasterSecurityLevel", "UNKNOWN");
            report.put("hardwareBacked", false);
            report.put("strongBoxSupported", false);
        }
        return report;
    }

    public byte[][] getHardwareAttestationChain(String nonce) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS);
            }
            KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN
            )
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(nonce.getBytes(StandardCharsets.UTF_8));
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    builder.setIsStrongBoxBacked(false);
                } catch (Throwable ignored) {}
            }
            generator.initialize(builder.build());
            generator.generateKeyPair();
            Certificate[] certificates = keyStore.getCertificateChain(KEY_ALIAS);
            if (certificates == null || certificates.length == 0) {
                return null;
            }
            byte[][] result = new byte[certificates.length][];
            for (int i = 0; i < certificates.length; i++) {
                result[i] = certificates[i].getEncoded();
            }
            return result;
        } catch (Exception e) {
            Log.e(TAG, "Hardware attestation generation failed", e);
            return null;
        }
    }

    public boolean isBootloaderLocked(List<byte[]> certBytesList) {
        try {
            ASN1Sequence rootOfTrust = getRootOfTrust(certBytesList);
            if (rootOfTrust == null) {
                return false;
            }
            for (int i = 0; i < rootOfTrust.size(); i++) {
                Object element = rootOfTrust.getObjectAt(i);
                if (element instanceof ASN1Boolean) {
                    return ((ASN1Boolean) element).isTrue();
                }
            }
            return false;
        } catch (Exception e) {
            Log.e(TAG, "Bootloader check failed", e);
            return false;
        }
    }

    public String getVerifiedBootState(List<byte[]> certBytesList) {
        try {
            ASN1Sequence rootOfTrust = getRootOfTrust(certBytesList);
            if (rootOfTrust == null) {
                return "UNKNOWN";
            }
            for (int i = 0; i < rootOfTrust.size(); i++) {
                Object element = rootOfTrust.getObjectAt(i);
                if (element instanceof ASN1Enumerated) {
                    int state = ((ASN1Enumerated) element).getValue().intValue();
                    return switch (state) {
                        case 0 -> "VERIFIED";
                        case 1 -> "SELF_SIGNED";
                        case 2 -> "UNVERIFIED";
                        case 3 -> "FAILED";
                        default -> "UNKNOWN";
                    };
                }
            }
            return "UNKNOWN";
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }

    private ASN1Sequence getRootOfTrust(List<byte[]> certBytesList) {
        if (certBytesList == null || certBytesList.isEmpty()) {
            return null;
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytesList.get(0)));
            byte[] extension = certificate.getExtensionValue(ATTESTATION_OID);
            if (extension == null) return null;
            ASN1OctetString octetString = ASN1OctetString.getInstance(extension);
            ASN1Sequence keyDescription = ASN1Sequence.getInstance(octetString.getOctets());
            for (int index = 0; index < keyDescription.size(); index++) {
                Object current = keyDescription.getObjectAt(index);
                if (!(current instanceof ASN1Sequence)) {
                    continue;
                }
                ASN1Sequence groupSequence = ASN1Sequence.getInstance(current);
                for (int i = 0; i < groupSequence.size(); i++) {
                    Object entry = groupSequence.getObjectAt(i);
                    if (entry instanceof ASN1TaggedObject) {
                        ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(entry);
                        if (tagged.getTagNo() == KM_TAG_ROOT_OF_TRUST) {
                            return ASN1Sequence.getInstance(tagged.getObject());
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Dynamic RootOfTrust parse failed", e);
        }
        return null;
    }

    private ASN1Sequence getKeyDescription(List<byte[]> certBytesList) {
        if (certBytesList == null || certBytesList.isEmpty()) {
            return null;
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytesList.get(0)));
            byte[] extension = certificate.getExtensionValue(ATTESTATION_OID);
            if (extension == null) return null;
            ASN1OctetString octetString = ASN1OctetString.getInstance(extension);
            return ASN1Sequence.getInstance(octetString.getOctets());
        } catch (Exception ignored) {}
        return null;
    }

    public String getAttestationSecurityLevel(List<byte[]> certBytesList) {
        try {
            ASN1Sequence keyDescription = getKeyDescription(certBytesList);
            if (keyDescription == null) return "UNKNOWN";
            ASN1Enumerated securityLevel = ASN1Enumerated.getInstance(keyDescription.getObjectAt(1));
            return securityLevelToString(securityLevel.getValue().intValue());
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }

    public String getKeymasterSecurityLevel(List<byte[]> certBytesList) {
        try {
            ASN1Sequence keyDescription = getKeyDescription(certBytesList);
            if (keyDescription == null) return "UNKNOWN";
            ASN1Enumerated securityLevel = ASN1Enumerated.getInstance(keyDescription.getObjectAt(3));
            return securityLevelToString(securityLevel.getValue().intValue());
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }

    private String securityLevelToString(int level) {
        return switch (level) {
            case 0 -> "SOFTWARE";
            case 1 -> "TRUSTED_ENVIRONMENT";
            case 2 -> "STRONGBOX";
            default -> "UNKNOWN";
        };
    }

    public boolean isDeviceRooted() {
        try {
            String buildTags = Build.TAGS;
            if (buildTags != null && buildTags.contains("test-keys")) {
                return true;
            }
            String[] paths = {
                    "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
                    "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su",
                    "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su",
                    "/system/xbin/busybox", "/system/bin/busybox"
            };
            for (String path : paths) {
                if (new File(path).exists()) return true;
            }
        } catch (Exception ignored) {}
        return false;
    }

    public boolean isHookingFrameworkDetected() {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.toLowerCase();
                if (line.contains("frida") || line.contains("xposed") || line.contains("substrate") || line.contains("zygisk") || line.contains("riru")) {
                    return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    public boolean isEmulator() {
        return Build.FINGERPRINT.startsWith("generic") || Build.MODEL.contains("Emulator") || Build.HARDWARE.contains("goldfish") || Build.HARDWARE.contains("ranchu");
    }

    public boolean isHardwareBackedKeyStore() {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            PrivateKey key = (PrivateKey) ks.getKey(KEY_ALIAS, null);
            if (key == null) return false;
            KeyFactory factory = KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
            KeyInfo info = factory.getKeySpec(key, KeyInfo.class);
            return info.isInsideSecureHardware();
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isStrongBoxSupported() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                && getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
    }
}