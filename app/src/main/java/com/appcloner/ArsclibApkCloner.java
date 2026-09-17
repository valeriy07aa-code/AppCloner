package com.appcloner;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.util.Log;

import androidx.core.content.FileProvider;

import com.android.tools.build.apksig.ApkSigner;
import com.android.tools.build.apksig.SignerConfig;
import com.reandroid.arsc.chunk.xml.AndroidManifestBlock;

import net.dongliu.apk.parser.ApkFile;
import net.dongliu.apk.parser.bean.ApkMeta;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.security.auth.x500.X500Principal;

/**
 * APK cloner using ARSCLib for binary XML modification
 * and apksig for proper APK signing.
 */
public class ArsclibApkCloner {

    private static final String TAG = "ArsclibApkCloner";
    private Context context;
    private File outputDir;
    private File tempDir;

    public ArsclibApkCloner(Context context) {
        this.context = context;
        this.outputDir = new File(context.getExternalFilesDir(null), "cloned");
        this.tempDir = new File(context.getCacheDir(), "temp_clone");

        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }
        if (!tempDir.exists()) {
            tempDir.mkdirs();
        }
    }

    public ApkMeta getApkMeta(String apkPath) {
        try (ApkFile apkFile = new ApkFile(new File(apkPath))) {
            return apkFile.getApkMeta();
        } catch (IOException e) {
            Log.e(TAG, "Error reading APK metadata", e);
            return null;
        }
    }

    public String getApkPath(String packageName) {
        try {
            PackageInfo packageInfo = context.getPackageManager()
                    .getPackageInfo(packageName, 0);
            if (packageInfo != null && packageInfo.applicationInfo != null) {
                return packageInfo.applicationInfo.sourceDir;
            }
        } catch (PackageManager.NameNotFoundException e) {
            Log.e(TAG, "Package not found: " + packageName, e);
        }
        return null;
    }

    /**
     * Clones APK: modify manifest + strip old signature + sign with new key
     */
    public String cloneWithNewPackage(String packageName, String newPackageName) {
        try {
            String sourcePath = getApkPath(packageName);
            if (sourcePath == null) {
                Log.e(TAG, "Source APK not found");
                return null;
            }

            String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault())
                    .format(new Date());
            String outputName = newPackageName.replaceAll("\\.", "_") + "_" + timestamp + ".apk";
            File unsignedFile = new File(tempDir, "unsigned_" + outputName);
            File signedFile = new File(outputDir, outputName);

            // Step 1: Extract and modify manifest
            byte[] manifestData = extractManifest(sourcePath);
            if (manifestData == null) {
                Log.e(TAG, "Failed to extract manifest");
                return null;
            }

            AndroidManifestBlock manifestBlock = new AndroidManifestBlock();
            manifestBlock.readBytes(new ByteArrayInputStream(manifestData));

            String originalPackage = manifestBlock.getPackageName();
            Log.d(TAG, "Original package: " + originalPackage);
            Log.d(TAG, "New package: " + newPackageName);

            manifestBlock.setPackageName(newPackageName);
            byte[] modifiedManifest = manifestBlock.getBytes();

            // Step 2: Rebuild APK WITHOUT old signature (skip META-INF/)
            boolean rebuilt = rebuildApkWithoutSignature(
                    sourcePath, unsignedFile.getAbsolutePath(), modifiedManifest);
            if (!rebuilt) {
                Log.e(TAG, "Failed to rebuild APK");
                return null;
            }

            // Step 3: Sign with a new key using apksig
            boolean signed = signApkWithApksig(unsignedFile.getAbsolutePath(),
                    signedFile.getAbsolutePath());
            if (!signed) {
                Log.e(TAG, "Failed to sign APK");
                return null;
            }

            // Cleanup unsigned
            unsignedFile.delete();

            Log.i(TAG, "APK cloned successfully: " + signedFile.getAbsolutePath());
            return signedFile.getAbsolutePath();

        } catch (Exception e) {
            Log.e(TAG, "Error cloning APK", e);
            return null;
        }
    }

    private byte[] extractManifest(String apkPath) {
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(apkPath))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().equals("AndroidManifest.xml")) {
                    return readAllBytes(zis);
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Error extracting manifest", e);
        }
        return null;
    }

    /**
     * Rebuilds APK, replacing manifest and STRIPPING old META-INF signature
     */
    private boolean rebuildApkWithoutSignature(String inputPath, String outputPath,
                                                byte[] modifiedManifest) {
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(inputPath));
             ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outputPath))) {

            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String entryName = entry.getName();

                // Skip old signature files
                if (entryName.startsWith("META-INF/")) {
                    continue;
                }

                ZipEntry newEntry = new ZipEntry(entryName);
                // Preserve method and time
                newEntry.setMethod(entry.getMethod());
                newEntry.setTime(entry.getTime());

                zos.putNextEntry(newEntry);

                if (entryName.equals("AndroidManifest.xml")) {
                    zos.write(modifiedManifest);
                } else {
                    byte[] buffer = new byte[8192];
                    int len;
                    while ((len = zis.read(buffer)) > 0) {
                        zos.write(buffer, 0, len);
                    }
                }
                zos.closeEntry();
            }

            zos.finish();
            return true;

        } catch (IOException e) {
            Log.e(TAG, "Error rebuilding APK", e);
            return false;
        }
    }

    /**
     * Signs APK using apksig library with a generated debug key
     */
    private boolean signApkWithApksig(String inputPath, String outputPath) {
        try {
            // Generate RSA key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();

            // Create self-signed certificate using Android's built-in classes
            // apksig accepts any X509 cert — we build a minimal one
            X509Certificate cert = createSelfSignedCert(keyPair);

            // Setup signer config
            SignerConfig signerConfig = new SignerConfig.Builder()
                    .setName("AppCloner")
                    .setPrivateKey(privateKey)
                    .setCertificates(Collections.singletonList(cert))
                    .build();

            List<SignerConfig> signerConfigs = new ArrayList<>();
            signerConfigs.add(signerConfig);

            // Sign the APK
            ApkSigner signer = new ApkSigner.Builder(signerConfigs)
                    .setInputApk(new File(inputPath))
                    .setOutputApk(new File(outputPath))
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(false)
                    .build();

            signer.sign();
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Error signing APK with apksig", e);
            return false;
        }
    }

    /**
     * Creates a minimal self-signed X.509 certificate
     * Uses BouncyCastle-style raw construction or Android's CertificateFactory
     */
    private X509Certificate createSelfSignedCert(KeyPair keyPair) throws Exception {
        // Build a minimal self-signed X.509 v3 certificate using
        // javax.security and sun security provider (available on Android)
        //
        // We use the approach: create a KeyStore with a self-signed entry
        String alias = "appcloner";
        char[] password = "appcloner".toCharArray();

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, password);

        // Generate self-signed cert via KeyPairGenerator + KeyStore
        // On Android, we can use a simpler approach: build the cert from scratch
        java.security.cert.Certificate[] chain = generateCertificate(keyPair);
        keyStore.setKeyEntry(alias, privateKey(keyPair), password, chain);

        return (X509Certificate) chain[0];
    }

    private PrivateKey privateKey(KeyPair kp) {
        return kp.getPrivate();
    }

    /**
     * Generates a self-signed certificate chain
     */
    private java.security.cert.Certificate[] generateCertificate(KeyPair keyPair) throws Exception {
        // On Android, we can use the following approach to create a self-signed cert:
        // 1. Use BouncyCastle (not available by default)
        // 2. Use X509CertImpl from sun.security (Android has this)
        // 3. Use a pre-generated cert

        // Simplest approach: use Android's built-in certificate generation
        // via the certificate factory

        // For Android, we'll use the approach of creating a minimal cert
        // that apksig will accept

        // Build a minimal ASN.1 encoded self-signed certificate
        byte[] certBytes = buildMinimalCert(keyPair);

        java.security.cert.CertificateFactory cf =
                java.security.cert.CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(certBytes));

        return new java.security.cert.Certificate[]{cert};
    }

    /**
     * Builds a minimal self-signed X.509 v3 certificate in DER format
     */
    private byte[] buildMinimalCert(KeyPair keyPair) throws Exception {
        // Use the approach of generating a PKCS12 keystore and extracting the cert
        // This is the most portable approach across Android versions

        // Alternative: use android.os.Build to check version and use appropriate method
        // For simplicity, we'll use a pre-encoded minimal cert template

        // Actually, the simplest approach that works on all Android versions:
        // Use the javax.net.ssl.KeyManagerFactory approach

        // Let's use a different, simpler approach: create a signed APK using
        // the JCA (Java Cryptography Architecture) directly

        // For now, use the Bouncy Castle light approach if available,
        // otherwise fall back to a pre-built test certificate

        // Generate using X509V3CertificateGenerator pattern
        // via raw ASN.1 DER encoding

        long now = System.currentTimeMillis();
        java.util.Date notBefore = new java.util.Date(now - 365L * 24 * 60 * 60 * 1000);
        java.util.Date notAfter = new java.util.Date(now + 365L * 10 * 24 * 60 * 60 * 1000);
        BigInteger serial = BigInteger.valueOf(now);

        String issuer = "CN=AppCloner Debug";

        // Build DER-encoded TBSCertificate
        // This is complex but necessary for proper Android compatibility

        // Let's use a much simpler approach: use the KeyStore setCertificateEntry
        // which internally creates a self-signed cert on some Android versions

        // Simplest working approach: use X509CertImpl if available
        try {
            // Try to use Android's internal certificate generation
            Class<?> certClass = Class.forName("sun.security.x509.X509CertImpl");
            // This class might not be available, so we need a fallback
        } catch (ClassNotFoundException e) {
            // Fallback: use a test certificate from the apksig test resources
        }

        // Use a hardcoded minimal valid self-signed certificate for debug purposes
        // This is a standard Android debug certificate format
        return getDebugCertificate(keyPair, serial, notBefore, notAfter, issuer);
    }

    /**
     * Returns a debug certificate. Uses reflection to access Android's
     * internal certificate generation, or a pre-built certificate.
     */
    private byte[] getDebugCertificate(KeyPair keyPair, BigInteger serial,
                                         java.util.Date notBefore, java.util.Date notAfter,
                                         String issuer) throws Exception {
        // Try to generate using Android's internal API
        try {
            // sun.security.x509.X509CertInfo is available on Android runtime
            Object certInfo = Class.forName("sun.security.x509.X509CertInfo").newInstance();

            // Set version
            Object version = Class.forName("sun.security.x509.CertificateVersion")
                    .getConstructor(int.class).newInstance(2); // v3
            setField(certInfo, "version", version);

            // Set serial number
            Object serialNum = Class.forName("sun.security.x509.CertificateSerialNumber")
                    .getConstructor(BigInteger.class).newInstance(serial);
            setField(certInfo, "serialNumber", serialNum);

            // Set validity
            Object validity = Class.forName("sun.security.x509.CertificateValidity")
                    .getConstructor(java.util.Date.class, java.util.Date.class)
                    .newInstance(notBefore, notAfter);
            setField(certInfo, "validity", validity);

            // Set subject and issuer (same for self-signed)
            Object x500Name = Class.forName("sun.security.x509.X500Name")
                    .getConstructor(String.class).newInstance(issuer);
            setField(certInfo, "subject", x500Name);
            setField(certInfo, "issuer", x500Name);

            // Set public key
            setField(certInfo, "key", Class.forName("sun.security.x509.CertificateX509Key")
                    .getConstructor(java.security.PublicKey.class)
                    .newInstance(keyPair.getPublic()));

            // Set algorithm
            setField(certInfo, "algorithmId", Class.forName("sun.security.x509.CertificateAlgorithmId")
                    .getConstructor(Class.forName("sun.security.x509.AlgorithmId"))
                    .newInstance(Class.forName("sun.security.x509.AlgorithmId")
                            .getMethod("get", String.class).invoke(null, "SHA256withRSA")));

            // Create the certificate
            Object certImpl = Class.forName("sun.security.x509.X509CertImpl")
                    .getConstructor(certInfo.getClass())
                    .newInstance(certInfo);

            // Sign it
            java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
            sig.initSign(keyPair.getPrivate());
            // sign and encode
            certImpl.getClass().getMethod("sign", java.security.PrivateKey.class, String.class)
                    .invoke(certImpl, keyPair.getPrivate(), "SHA256withRSA");

            // Get encoded form
            return (byte[]) certImpl.getClass().getMethod("getEncoded").invoke(certImpl);

        } catch (Exception e) {
            Log.w(TAG, "Could not generate cert via sun.security, using fallback: " + e.getMessage());
            return generateFallbackCert(keyPair, serial, notBefore, notAfter);
        }
    }

    private void setField(Object obj, String fieldName, Object value) throws Exception {
        try {
            java.lang.reflect.Field field = obj.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(obj, value);
        } catch (NoSuchFieldException e) {
            // Some versions use different field names, skip
            Log.d(TAG, "Field not found: " + fieldName);
        }
    }

    /**
     * Fallback: build a raw DER-encoded self-signed X.509v3 certificate
     */
    private byte[] generateFallbackCert(KeyPair keyPair, BigInteger serial,
                                          java.util.Date notBefore, java.util.Date notAfter) throws Exception {
        // Build a minimal valid X.509 v3 certificate via raw ASN.1 DER encoding
        // This is verbose but guaranteed to work on any JRE

        byte[] issuerDer = encodeX500Name("CN=AppCloner Debug");
        byte[] validityDer = encodeValidity(notBefore, notAfter);
        byte[] spkiDer = encodeSubjectPublicKeyInfo(keyPair.getPublic());
        byte[] tbs = encodeTbsCertificate(serial, issuerDer, validityDer, issuerDer, spkiDer);

        // Sign the TBSCertificate
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
        sig.initSign(keyPair.getPrivate());
        sig.update(tbs);
        byte[] signature = sig.sign();

        byte[] sigAlgDer = encodeAlgorithmIdentifier("1.2.840.113549.1.1.11"); // SHA256withRSA
        byte[] sigValueDer = encodeBitString(signature);

        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        return encodeSequence(concat(tbs, sigAlgDer, sigValueDer));
    }

    // --- Minimal ASN.1 DER encoding helpers ---

    private byte[] encodeSequence(byte[] content) {
        return encodeTlv(0x30, content);
    }

    private byte[] encodeSet(byte[] content) {
        return encodeTlv(0x31, content);
    }

    private byte[] encodeTlv(int tag, byte[] content) {
        byte[] len = encodeLength(content.length);
        byte[] result = new byte[1 + len.length + content.length];
        result[0] = (byte) tag;
        System.arraycopy(len, 0, result, 1, len.length);
        System.arraycopy(content, 0, result, 1 + len.length, content.length);
        return result;
    }

    private byte[] encodeLength(int length) {
        if (length < 0x80) {
            return new byte[]{(byte) length};
        } else if (length < 0x100) {
            return new byte[]{(byte) 0x81, (byte) length};
        } else {
            return new byte[]{(byte) 0x82, (byte) (length >> 8), (byte) length};
        }
    }

    private byte[] encodeInteger(BigInteger value) {
        byte[] bytes = value.toByteArray();
        return encodeTlv(0x02, bytes);
    }

    private byte[] encodeObjectIdentifier(String oid) {
        String[] parts = oid.split("\\.");
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write(Integer.parseInt(parts[0]) * 40 + Integer.parseInt(parts[1]));
        for (int i = 2; i < parts.length; i++) {
            long v = Long.parseLong(parts[i]);
            if (v < 0x80) {
                out.write((int) v);
            } else {
                // Encode multi-byte
                int[] bytes = new int[8];
                int pos = 0;
                bytes[pos++] = (int) (v & 0x7F);
                v >>= 7;
                while (v > 0) {
                    bytes[pos++] = (int) (v & 0x7F) | 0x80;
                    v >>= 7;
                }
                for (int j = pos - 1; j >= 0; j--) {
                    out.write(bytes[j]);
                }
            }
        }
        return encodeTlv(0x06, out.toByteArray());
    }

    private byte[] encodeOctetString(byte[] data) {
        return encodeTlv(0x04, data);
    }

    private byte[] encodeBitString(byte[] data) {
        // BIT STRING with 0 unused bits
        byte[] content = new byte[data.length + 1];
        content[0] = 0; // 0 unused bits
        System.arraycopy(data, 0, content, 1, data.length);
        return encodeTlv(0x03, content);
    }

    private byte[] encodeUtf8String(String str) {
        return encodeTlv(0x0C, str.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private byte[] encodeUtcTime(java.util.Date date) {
        java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("yyMMddHHmmss'Z'",
                java.util.Locale.US);
        sdf.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        return encodeTlv(0x17, sdf.format(date).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    private byte[] encodeAlgorithmIdentifier(String oid) {
        return encodeSequence(encodeObjectIdentifier(oid));
    }

    private byte[] encodeX500Name(String dn) {
        // CN=AppCloner Debug -> SEQUENCE { SET { SEQUENCE { OID(2.5.4.3), UTF8String } } }
        String cn = dn.replace("CN=", "");
        byte[] attrType = encodeObjectIdentifier("2.5.4.3"); // CN
        byte[] attrValue = encodeUtf8String(cn);
        byte[] attr = encodeSequence(concat(attrType, attrValue));
        byte[] set = encodeSet(attr);
        return encodeSequence(set);
    }

    private byte[] encodeValidity(java.util.Date notBefore, java.util.Date notAfter) {
        return encodeSequence(concat(encodeUtcTime(notBefore), encodeUtcTime(notAfter)));
    }

    private byte[] encodeSubjectPublicKeyInfo(java.security.PublicKey publicKey) throws Exception {
        byte[] algId = encodeAlgorithmIdentifier("1.2.840.113549.1.1.1"); // RSA
        byte[] pubKeyBits = encodeBitString(publicKey.getEncoded());
        // The public key encoded is already SubjectPublicKeyInfo, extract the key part
        // Actually publicKey.getEncoded() returns full SubjectPublicKeyInfo
        // So we just wrap it in a sequence manually
        return publicKey.getEncoded(); // This is already the full SPKI DER
    }

    private byte[] encodeTbsCertificate(BigInteger serial, byte[] issuer, byte[] validity,
                                          byte[] subject, byte[] spki) {
        // Version [0] EXPLICIT INTEGER (2) for v3
        byte[] version = encodeTlv(0xA0, encodeInteger(BigInteger.valueOf(2)));
        byte[] serialNum = encodeInteger(serial);
        byte[] sigAlg = encodeAlgorithmIdentifier("1.2.840.113549.1.1.11"); // SHA256withRSA

        return encodeSequence(concat(version, serialNum, sigAlg, issuer, validity, subject, spki));
    }

    private byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] result = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }

    public boolean installApk(String apkPath) {
        try {
            File apkFile = new File(apkPath);
            if (!apkFile.exists()) return false;

            Uri apkUri;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                apkUri = FileProvider.getUriForFile(context,
                        context.getPackageName() + ".provider", apkFile);
            } else {
                apkUri = Uri.fromFile(apkFile);
            }

            Intent intent = new Intent(Intent.ACTION_VIEW);
            intent.setDataAndType(apkUri, "application/vnd.android.package-archive");
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            context.startActivity(intent);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Error installing APK", e);
            return false;
        }
    }

    public boolean shareApk(String apkPath) {
        try {
            File apkFile = new File(apkPath);
            if (!apkFile.exists()) return false;

            Uri apkUri;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                apkUri = FileProvider.getUriForFile(context,
                        context.getPackageName() + ".provider", apkFile);
            } else {
                apkUri = Uri.fromFile(apkFile);
            }

            Intent shareIntent = new Intent(Intent.ACTION_SEND);
            shareIntent.setType("application/vnd.android.package-archive");
            shareIntent.putExtra(Intent.EXTRA_STREAM, apkUri);
            shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            context.startActivity(Intent.createChooser(shareIntent, "Share APK"));
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Error sharing APK", e);
            return false;
        }
    }

    public File getOutputDir() {
        return outputDir;
    }

    public void cleanup() {
        deleteRecursive(tempDir);
    }

    private void deleteRecursive(File file) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursive(child);
                }
            }
        }
        file.delete();
    }

    private byte[] readAllBytes(InputStream is) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[8192];
        int len;
        while ((len = is.read(data)) != -1) {
            buffer.write(data, 0, len);
        }
        return buffer.toByteArray();
    }
}
