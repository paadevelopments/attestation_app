package com.paadevelopments.attestation_app;

import androidx.annotation.NonNull;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Debug;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;
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
import java.security.MessageDigest;
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

    private static final String TAG =
            "MPOC_ATTESTATION";

    private static final String CHANNEL =
            "com.paadevelopments.attestation_app/security";

    private static final String KEY_ALIAS =
            "mpoc_attestation_key";

    /*
     * Android Hardware Attestation Extension OID
     */
    private static final String ATTESTATION_OID =
            "1.3.6.1.4.1.11129.2.1.17";

    /*
     * Keymaster Tag
     */
    private static final int KM_TAG_ROOT_OF_TRUST =
            704;

    @Override
    public void configureFlutterEngine(
            @NonNull FlutterEngine flutterEngine
    ) {

        super.configureFlutterEngine(flutterEngine);

        new MethodChannel(
                flutterEngine
                        .getDartExecutor()
                        .getBinaryMessenger(),
                CHANNEL
        ).setMethodCallHandler((call, result) -> {

            switch (call.method) {

                /*
                 * =====================================================
                 * BUILD SECURITY REPORT
                 * =====================================================
                 */

                case "getSecurityReport":

                    try {

                        String nonce =
                                call.argument("nonce");

                        if (nonce == null ||
                                nonce.trim().isEmpty()) {

                            result.error(
                                    "INVALID_NONCE",
                                    "Nonce cannot be null",
                                    null
                            );

                            return;
                        }

                        Map<String, Object> report =
                                buildSecurityReport(
                                        nonce
                                );

                        result.success(report);

                    } catch (Exception e) {

                        Log.e(
                                TAG,
                                "Security report generation failed",
                                e
                        );

                        result.error(
                                "ATTESTATION_ERROR",
                                e.getMessage(),
                                null
                        );
                    }

                    break;

                /*
                 * =====================================================
                 * TEMP LOCAL PARSER TEST ENDPOINT
                 * =====================================================
                 */

                case "checkBootloaderStatus":

                    try {

                        List<byte[]> chain =
                                call.argument(
                                        "certificateChain"
                                );

                        result.success(
                                isBootloaderLocked(chain)
                        );

                    } catch (Exception e) {

                        result.error(
                                "BOOTLOADER_ERROR",
                                e.getMessage(),
                                null
                        );
                    }

                    break;

                default:
                    result.notImplemented();
                    break;
            }
        });
    }

    /*
     * =========================================================
     * BUILD SECURITY REPORT
     * =========================================================
     */

    private Map<String, Object> buildSecurityReport(
            String nonce
    ) {

        Map<String, Object> report =
                new HashMap<>();

        report.put(
                "manufacturer",
                Build.MANUFACTURER
        );

        report.put(
                "brand",
                Build.BRAND
        );

        report.put(
                "model",
                Build.MODEL
        );

        report.put(
                "device",
                Build.DEVICE
        );

        report.put(
                "product",
                Build.PRODUCT
        );

        report.put(
                "sdkInt",
                Build.VERSION.SDK_INT
        );

        report.put(
                "androidVersion",
                Build.VERSION.RELEASE
        );

        report.put(
                "isRooted",
                isDeviceRooted()
        );

        report.put(
                "isHookDetected",
                isHookingFrameworkDetected()
        );

        report.put(
                "isDebuggerAttached",
                Debug.isDebuggerConnected()
        );

        report.put(
                "isEmulator",
                isEmulator()
        );

        report.put(
                "isSELinuxEnforced",
                isSELinuxEnforced()
        );

        report.put(
                "apkSignatureHash",
                getApkSignatureHash()
        );

        byte[][] chain =
                getHardwareAttestationChain(
                        nonce
                );

        if (chain != null) {

            List<byte[]> certList =
                    new ArrayList<>();

            Collections.addAll(
                    certList,
                    chain
            );

            report.put(
                    "certificateChain",
                    certList
            );

            report.put(
                    "isBootloaderLocked",
                    isBootloaderLocked(certList)
            );

            report.put(
                    "verifiedBootState",
                    getVerifiedBootState(certList)
            );

            report.put(
                    "attestationSecurityLevel",
                    getAttestationSecurityLevel(
                            certList
                    )
            );

            report.put(
                    "keymasterSecurityLevel",
                    getKeymasterSecurityLevel(
                            certList
                    )
            );

            report.put(
                    "hardwareBacked",
                    isHardwareBackedKeyStore()
            );

            report.put(
                    "strongBoxSupported",
                    isStrongBoxSupported()
            );

        } else {

            report.put(
                    "certificateChain",
                    null
            );

            report.put(
                    "isBootloaderLocked",
                    false
            );

            report.put(
                    "verifiedBootState",
                    "UNKNOWN"
            );

            report.put(
                    "attestationSecurityLevel",
                    "UNKNOWN"
            );

            report.put(
                    "keymasterSecurityLevel",
                    "UNKNOWN"
            );

            report.put(
                    "hardwareBacked",
                    false
            );

            report.put(
                    "strongBoxSupported",
                    false
            );
        }

        return report;
    }

    /*
     * =========================================================
     * GENERATE HARDWARE ATTESTATION
     * =========================================================
     */

    public byte[][] getHardwareAttestationChain(
            String nonce
    ) {

        try {

            KeyStore keyStore =
                    KeyStore.getInstance(
                            "AndroidKeyStore"
                    );

            keyStore.load(null);

            if (keyStore.containsAlias(KEY_ALIAS)) {

                keyStore.deleteEntry(KEY_ALIAS);
            }

            KeyPairGenerator generator =
                    KeyPairGenerator.getInstance(
                            KeyProperties.KEY_ALGORITHM_EC,
                            "AndroidKeyStore"
                    );

            KeyGenParameterSpec.Builder builder =
                    new KeyGenParameterSpec.Builder(
                            KEY_ALIAS,
                            KeyProperties.PURPOSE_SIGN
                    )
                            .setDigests(
                                    KeyProperties.DIGEST_SHA256
                            )
                            .setAttestationChallenge(
                                    nonce.getBytes(
                                            StandardCharsets.UTF_8
                                    )
                            );

            /*
             * StrongBox support
             */

            if (Build.VERSION.SDK_INT >=
                    Build.VERSION_CODES.P) {

                try {

                    builder.setIsStrongBoxBacked(
                            false
                    );

                } catch (Throwable ignored) {
                }
            }

            generator.initialize(
                    builder.build()
            );

            generator.generateKeyPair();

            Certificate[] certificates =
                    keyStore.getCertificateChain(
                            KEY_ALIAS
                    );

            if (certificates == null ||
                    certificates.length == 0) {

                return null;
            }

            byte[][] result =
                    new byte[certificates.length][];

            for (int i = 0;
                 i < certificates.length;
                 i++) {

                result[i] =
                        certificates[i].getEncoded();
            }

            return result;

        } catch (Exception e) {

            Log.e(
                    TAG,
                    "Hardware attestation generation failed",
                    e
            );

            return null;
        }
    }

    /*
     * =========================================================
     * BOOTLOADER LOCK STATUS
     * =========================================================
     */

    public boolean isBootloaderLocked(
            List<byte[]> certBytesList
    ) {

        try {

            ASN1Sequence rootOfTrust =
                    getRootOfTrust(
                            certBytesList
                    );

            if (rootOfTrust == null ||
                    rootOfTrust.size() < 3) {

                return false;
            }

            ASN1Boolean deviceLocked =
                    ASN1Boolean.getInstance(
                            rootOfTrust.getObjectAt(1)
                    );

            ASN1Enumerated verifiedBootState =
                    ASN1Enumerated.getInstance(
                            rootOfTrust.getObjectAt(2)
                    );

            /*
             * VERIFIED = 0
             */

            return deviceLocked.isTrue()
                    &&
                    verifiedBootState
                            .getValue()
                            .intValue() == 0;

        } catch (Exception e) {

            Log.e(
                    TAG,
                    "Bootloader check failed",
                    e
            );

            return false;
        }
    }

    /*
     * =========================================================
     * VERIFIED BOOT STATE
     * =========================================================
     */

    public String getVerifiedBootState(
            List<byte[]> certBytesList
    ) {

        try {

            ASN1Sequence rootOfTrust =
                    getRootOfTrust(
                            certBytesList
                    );

            if (rootOfTrust == null ||
                    rootOfTrust.size() < 3) {

                return "UNKNOWN";
            }

            ASN1Enumerated verifiedBootState =
                    ASN1Enumerated.getInstance(
                            rootOfTrust.getObjectAt(2)
                    );

            int state =
                    verifiedBootState
                            .getValue()
                            .intValue();

            switch (state) {

                case 0:
                    return "VERIFIED";

                case 1:
                    return "SELF_SIGNED";

                case 2:
                    return "UNVERIFIED";

                case 3:
                    return "FAILED";

                default:
                    return "UNKNOWN";
            }

        } catch (Exception e) {

            return "UNKNOWN";
        }
    }

    /*
     * =========================================================
     * ROOT OF TRUST PARSER
     * =========================================================
     */

    private ASN1Sequence getRootOfTrust(
            List<byte[]> certBytesList
    ) {

        if (certBytesList == null ||
                certBytesList.isEmpty()) {

            return null;
        }

        try {

            CertificateFactory factory =
                    CertificateFactory.getInstance(
                            "X.509"
                    );

            /*
             * FULL CERTIFICATE CHAIN TRAVERSAL
             */

            for (byte[] certBytes : certBytesList) {

                try {

                    X509Certificate certificate =
                            (X509Certificate)
                                    factory.generateCertificate(
                                            new ByteArrayInputStream(
                                                    certBytes
                                            )
                                    );

                    byte[] extension =
                            certificate.getExtensionValue(
                                    ATTESTATION_OID
                            );

                    if (extension == null) {
                        continue;
                    }

                    ASN1OctetString octetString =
                            ASN1OctetString.getInstance(
                                    extension
                            );

                    ASN1Sequence keyDescription =
                            ASN1Sequence.getInstance(
                                    octetString.getOctets()
                            );

                    /*
                     * Android schema variability:
                     *
                     * uniqueId may be omitted.
                     * teeEnforced can become index 6 or 7.
                     */

                    int[] probableIndexes =
                            {6, 7};

                    for (int targetIndex :
                            probableIndexes) {

                        if (targetIndex >=
                                keyDescription.size()) {

                            continue;
                        }

                        Object current =
                                keyDescription.getObjectAt(
                                        targetIndex
                                );

                        if (!(current instanceof ASN1Sequence)) {
                            continue;
                        }

                        ASN1Sequence teeEnforced =
                                ASN1Sequence.getInstance(
                                        current
                                );

                        for (int i = 0;
                             i < teeEnforced.size();
                             i++) {

                            Object entry =
                                    teeEnforced.getObjectAt(i);

                            if (!(entry instanceof ASN1TaggedObject)) {
                                continue;
                            }

                            ASN1TaggedObject tagged =
                                    ASN1TaggedObject.getInstance(
                                            entry
                                    );

                            /*
                             * RootOfTrust = Tag 704
                             */

                            if (tagged.getTagNo()
                                    == KM_TAG_ROOT_OF_TRUST) {

                                /*
                                 * BC 1.70 explicit-tag parse
                                 */

                                return ASN1Sequence.getInstance(
                                        tagged,
                                        false
                                );
                            }
                        }
                    }

                } catch (Exception inner) {

                    Log.w(
                            TAG,
                            "Skipping malformed certificate",
                            inner
                    );
                }
            }

        } catch (Exception e) {

            Log.e(
                    TAG,
                    "RootOfTrust parse failed",
                    e
            );
        }

        return null;
    }

    /*
     * =========================================================
     * KEY DESCRIPTION PARSER
     * =========================================================
     */

    private ASN1Sequence getKeyDescription(
            List<byte[]> certBytesList
    ) {

        if (certBytesList == null ||
                certBytesList.isEmpty()) {

            return null;
        }

        try {

            CertificateFactory factory =
                    CertificateFactory.getInstance(
                            "X.509"
                    );

            for (byte[] certBytes :
                    certBytesList) {

                try {

                    X509Certificate certificate =
                            (X509Certificate)
                                    factory.generateCertificate(
                                            new ByteArrayInputStream(
                                                    certBytes
                                            )
                                    );

                    byte[] extension =
                            certificate.getExtensionValue(
                                    ATTESTATION_OID
                            );

                    if (extension == null) {
                        continue;
                    }

                    ASN1OctetString octetString =
                            ASN1OctetString.getInstance(
                                    extension
                            );

                    return ASN1Sequence.getInstance(
                            octetString.getOctets()
                    );

                } catch (Exception ignored) {
                }
            }

        } catch (Exception ignored) {
        }

        return null;
    }

    /*
     * =========================================================
     * SECURITY LEVELS
     * =========================================================
     */

    public String getAttestationSecurityLevel(
            List<byte[]> certBytesList
    ) {

        try {

            ASN1Sequence keyDescription =
                    getKeyDescription(
                            certBytesList
                    );

            if (keyDescription == null) {
                return "UNKNOWN";
            }

            ASN1Enumerated securityLevel =
                    ASN1Enumerated.getInstance(
                            keyDescription.getObjectAt(1)
                    );

            return securityLevelToString(
                    securityLevel
                            .getValue()
                            .intValue()
            );

        } catch (Exception e) {

            return "UNKNOWN";
        }
    }

    public String getKeymasterSecurityLevel(
            List<byte[]> certBytesList
    ) {

        try {

            ASN1Sequence keyDescription =
                    getKeyDescription(
                            certBytesList
                    );

            if (keyDescription == null) {
                return "UNKNOWN";
            }

            ASN1Enumerated securityLevel =
                    ASN1Enumerated.getInstance(
                            keyDescription.getObjectAt(3)
                    );

            return securityLevelToString(
                    securityLevel
                            .getValue()
                            .intValue()
            );

        } catch (Exception e) {

            return "UNKNOWN";
        }
    }

    private String securityLevelToString(
            int level
    ) {

        switch (level) {

            case 0:
                return "SOFTWARE";

            case 1:
                return "TRUSTED_ENVIRONMENT";

            case 2:
                return "STRONGBOX";

            default:
                return "UNKNOWN";
        }
    }

    /*
     * =========================================================
     * HARDWARE KEYSTORE CHECK
     * =========================================================
     */

    public boolean isHardwareBackedKeyStore() {

        try {

            KeyStore ks =
                    KeyStore.getInstance(
                            "AndroidKeyStore"
                    );

            ks.load(null);

            PrivateKey privateKey =
                    (PrivateKey) ks.getKey(
                            KEY_ALIAS,
                            null
                    );

            if (privateKey == null) {
                return false;
            }

            KeyFactory factory =
                    KeyFactory.getInstance(
                            privateKey.getAlgorithm(),
                            "AndroidKeyStore"
                    );

            KeyInfo keyInfo =
                    factory.getKeySpec(
                            privateKey,
                            KeyInfo.class
                    );

            return keyInfo.isInsideSecureHardware();

        } catch (Exception e) {

            return false;
        }
    }

    /*
     * =========================================================
     * STRONGBOX SUPPORT
     * =========================================================
     */

    public boolean isStrongBoxSupported() {

        if (Build.VERSION.SDK_INT <
                Build.VERSION_CODES.P) {

            return false;
        }

        return getPackageManager()
                .hasSystemFeature(
                        PackageManager
                                .FEATURE_STRONGBOX_KEYSTORE
                );
    }

    /*
     * =========================================================
     * APK SIGNATURE HASH
     * =========================================================
     */

    public String getApkSignatureHash() {

        try {

            PackageInfo packageInfo =
                    getPackageManager()
                            .getPackageInfo(
                                    getPackageName(),
                                    PackageManager.GET_SIGNATURES
                            );

            Signature signature =
                    packageInfo.signatures[0];

            MessageDigest digest =
                    MessageDigest.getInstance(
                            "SHA-256"
                    );

            byte[] hash =
                    digest.digest(
                            signature.toByteArray()
                    );

            return Base64.encodeToString(
                    hash,
                    Base64.NO_WRAP
            );

        } catch (Exception e) {

            return null;
        }
    }

    /*
     * =========================================================
     * ROOT DETECTION
     * =========================================================
     */

    public boolean isDeviceRooted() {

        try {

            String buildTags =
                    Build.TAGS;

            if (buildTags != null &&
                    buildTags.contains("test-keys")) {

                return true;
            }

            String[] paths = {

                    "/system/app/Superuser.apk",
                    "/sbin/su",
                    "/system/bin/su",
                    "/system/xbin/su",
                    "/data/local/xbin/su",
                    "/data/local/bin/su",
                    "/system/sd/xbin/su",
                    "/system/bin/failsafe/su",
                    "/data/local/su",
                    "/system/xbin/busybox",
                    "/system/bin/busybox"
            };

            for (String path : paths) {

                if (new File(path).exists()) {
                    return true;
                }
            }

        } catch (Exception ignored) {
        }

        return false;
    }

    /*
     * =========================================================
     * HOOKING DETECTION
     * =========================================================
     */

    public boolean isHookingFrameworkDetected() {

        BufferedReader reader = null;

        try {

            reader =
                    new BufferedReader(
                            new FileReader(
                                    "/proc/self/maps"
                            )
                    );

            String line;

            while ((line = reader.readLine()) != null) {

                line = line.toLowerCase();

                if (line.contains("frida")
                        ||
                        line.contains("xposed")
                        ||
                        line.contains("substrate")
                        ||
                        line.contains("zygisk")
                        ||
                        line.contains("riru")) {

                    return true;
                }
            }

        } catch (Exception ignored) {

        } finally {

            try {

                if (reader != null) {
                    reader.close();
                }

            } catch (Exception ignored) {
            }
        }

        return false;
    }

    /*
     * =========================================================
     * EMULATOR DETECTION
     * =========================================================
     */

    public boolean isEmulator() {

        return Build.FINGERPRINT.startsWith("generic")
                ||
                Build.MODEL.contains("Emulator")
                ||
                Build.HARDWARE.contains("goldfish")
                ||
                Build.HARDWARE.contains("ranchu");
    }

    /*
     * =========================================================
     * SELINUX STATUS
     * =========================================================
     */

    public boolean isSELinuxEnforced() {

        BufferedReader reader = null;

        try {

            File file =
                    new File("/sys/fs/selinux/enforce");

            if (!file.exists()) {
                return false;
            }

            reader =
                    new BufferedReader(
                            new FileReader(file)
                    );

            String value = reader.readLine();

            return "1".equals(value);

        } catch (Exception e) {

            return false;

        } finally {

            try {

                if (reader != null) {
                    reader.close();
                }

            } catch (Exception ignored) {
            }
        }
    }
}