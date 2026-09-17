package com.appcloner;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.util.Log;

import androidx.core.content.FileProvider;

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
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * APK cloner using ARSCLib for binary XML modification.
 * Signs APK using standard Java JAR signing (v1 scheme).
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

            // Step 1: Modify manifest
            byte[] manifestData = extractManifest(sourcePath);
            if (manifestData == null) {
                Log.e(TAG, "Failed to extract manifest");
                return null;
            }

            AndroidManifestBlock manifestBlock = new AndroidManifestBlock();
            manifestBlock.readBytes(new ByteArrayInputStream(manifestData));

            String originalPackage = manifestBlock.getPackageName();
            Log.d(TAG, "Original package: " + originalPackage + " -> " + newPackageName);

            manifestBlock.setPackageName(newPackageName);
            byte[] modifiedManifest = manifestBlock.getBytes();

            // Step 2: Rebuild APK without old signature
            boolean rebuilt = rebuildApk(sourcePath, unsignedFile.getAbsolutePath(),
                    modifiedManifest);
            if (!rebuilt) {
                Log.e(TAG, "Failed to rebuild APK");
                return null;
            }

            // Step 3: Sign APK (v1 JAR signing)
            boolean signed = signApkV1(unsignedFile.getAbsolutePath(),
                    signedFile.getAbsolutePath());
            if (!signed) {
                Log.e(TAG, "Failed to sign APK");
                return null;
            }

            unsignedFile.delete();
            Log.i(TAG, "APK cloned: " + signedFile.getAbsolutePath());
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
     * Rebuilds APK, replacing manifest and stripping old META-INF/
     */
    private boolean rebuildApk(String inputPath, String outputPath, byte[] modifiedManifest) {
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(inputPath));
             ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outputPath))) {

            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();

                // Skip old signature
                if (name.startsWith("META-INF/")) {
                    continue;
                }

                ZipEntry newEntry = new ZipEntry(name);
                newEntry.setMethod(entry.getMethod());
                zos.putNextEntry(newEntry);

                if (name.equals("AndroidManifest.xml")) {
                    zos.write(modifiedManifest);
                } else {
                    byte[] buf = new byte[8192];
                    int len;
                    while ((len = zis.read(buf)) > 0) {
                        zos.write(buf, 0, len);
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
     * Signs APK using v1 JAR signing scheme.
     * This is compatible with all Android versions.
     */
    private boolean signApkV1(String inputPath, String outputPath) {
        try {
            // Generate signing key
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();

            // Generate self-signed certificate
            X509Certificate cert = generateCert(keyPair);

            // Read all entries from unsigned APK
            Map<String, byte[]> entries = new HashMap<>();
            Map<String, ZipEntry> entryMeta = new HashMap<>();
            try (ZipInputStream zis = new ZipInputStream(new FileInputStream(inputPath))) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    String name = entry.getName();
                    entries.put(name, readAllBytes(zis));
                    entryMeta.put(name, entry);
                }
            }

            // Calculate SHA-1 digests for all entries
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            Manifest manifest = new Manifest();
            Attributes mainAttrs = manifest.getMainAttributes();
            mainAttrs.put(Attributes.Name.MANIFEST_VERSION, "1.0");
            mainAttrs.put(new Attributes.Name("Created-By"), "AppCloner");

            // Build MANIFEST.MF entries
            StringBuilder manifestEntries = new StringBuilder();
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                String name = e.getKey();
                byte[] data = e.getValue();

                String sha1B64 = android.util.Base64.encodeToString(
                        sha1.digest(data), android.util.Base64.NO_WRAP);
                String sha256B64 = android.util.Base64.encodeToString(
                        sha256.digest(data), android.util.Base64.NO_WRAP);

                Attributes attrs = new Attributes();
                attrs.put(new Attributes.Name("SHA-256-Digest"), sha256B64);
                manifest.getEntries().put(name, attrs);
            }

            // Write MANIFEST.MF
            ByteArrayOutputStream manifestBaos = new ByteArrayOutputStream();
            manifest.write(manifestBaos);
            byte[] manifestBytes = manifestBaos.toByteArray();

            // Build CERT.SF (signature file)
            StringBuilder sfContent = new StringBuilder();
            sfContent.append("Signature-Version: 1.0\r\n");
            sfContent.append("Created-By: AppCloner\r\n");
            sfContent.append("SHA-256-Digest-Manifest: ");
            sfContent.append(android.util.Base64.encodeToString(
                    sha256.digest(manifestBytes), android.util.Base64.NO_WRAP));
            sfContent.append("\r\n\r\n");

            for (Map.Entry<String, Attributes> e : manifest.getEntries().entrySet()) {
                String name = e.getKey();
                Attributes attrs = e.getValue();

                sfContent.append("Name: ").append(name).append("\r\n");
                for (Map.Entry<Object, Object> attr : attrs.entrySet()) {
                    sfContent.append(attr.getKey().toString()).append(": ")
                            .append(attr.getValue().toString()).append("\r\n");
                }
                // Add SHA-256-Digest of the manifest section
                // Build the section bytes
                StringBuilder sectionSb = new StringBuilder();
                sectionSb.append("Name: ").append(name).append("\r\n");
                for (Map.Entry<Object, Object> attr : attrs.entrySet()) {
                    sectionSb.append(attr.getKey().toString()).append(": ")
                            .append(attr.getValue().toString()).append("\r\n");
                }
                sectionSb.append("\r\n");
                String sectionSha256 = android.util.Base64.encodeToString(
                        sha256.digest(sectionSb.toString().getBytes("UTF-8")),
                        android.util.Base64.NO_WRAP);
                sfContent.append("SHA-256-Digest-Manifest-Main-Attributes: ").append(sectionSha256).append("\r\n");
                sfContent.append("\r\n");
            }

            byte[] sfBytes = sfContent.toString().getBytes("UTF-8");

            // Sign CERT.SF to produce CERT.RSA
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(privateKey);
            sig.update(sfBytes);
            byte[] signatureBytes = sig.sign();

            // Build PKCS#7 signed data
            byte[] pkcs7 = buildPkcs7(sfBytes, signatureBytes, cert);

            // Write signed APK
            try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outputPath))) {
                // Write all original entries
                for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                    ZipEntry newEntry = new ZipEntry(e.getKey());
                    zos.putNextEntry(newEntry);
                    zos.write(e.getValue());
                    zos.closeEntry();
                }

                // Write META-INF/MANIFEST.MF
                zos.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
                zos.write(manifestBytes);
                zos.closeEntry();

                // Write META-INF/CERT.SF
                zos.putNextEntry(new ZipEntry("META-INF/CERT.SF"));
                zos.write(sfBytes);
                zos.closeEntry();

                // Write META-INF/CERT.RSA (PKCS#7 signature)
                zos.putNextEntry(new ZipEntry("META-INF/CERT.RSA"));
                zos.write(pkcs7);
                zos.closeEntry();

                zos.finish();
            }

            return true;

        } catch (Exception e) {
            Log.e(TAG, "Error signing APK", e);
            return false;
        }
    }

    /**
     * Builds a minimal PKCS#7 SignedData structure
     */
    private byte[] buildPkcs7(byte[] content, byte[] signature, X509Certificate cert)
            throws Exception {
        // PKCS#7 ContentInfo ::= SEQUENCE {
        //   contentType OID,
        //   content [0] EXPLICIT SignedData
        // }

        byte[] certDer = cert.getEncoded();

        // SignedData ::= SEQUENCE {
        //   version INTEGER (1),
        //   digestAlgorithms SET { AlgorithmIdentifier },
        //   contentInfo ContentInfo (empty),
        //   certificates [0] IMPLICIT Certificate,
        //   signerInfos SET { SignerInfo }
        // }

        // AlgorithmIdentifier for SHA-256
        byte[] sha256Alg = encodeSequence(encodeOid("2.16.840.1.101.3.4.2.1"));

        // SignerInfo ::= SEQUENCE {
        //   version INTEGER (1),
        //   issuerAndSerialNumber SEQUENCE { issuer Name, serial INTEGER },
        //   digestAlgorithm AlgorithmIdentifier,
        //   authenticatedAttributes [0] IMPLICIT Attributes (optional),
        //   digestEncryptionAlgorithm AlgorithmIdentifier,
        //   encryptedDigest OCTET STRING
        // }

        byte[] rsaAlg = encodeSequence(encodeOid("1.2.840.113549.1.1.1"));

        // issuerAndSerialNumber
        byte[] issuerDer = cert.getIssuerX500Principal().getEncoded();
        byte[] serialNum = encodeInteger(cert.getSerialNumber());
        byte[] issuerAndSerial = encodeSequence(concat(issuerDer, serialNum));

        // SignerInfo
        byte[] signerInfo = encodeSequence(concat(
                encodeInteger(BigInteger.ONE),  // version
                issuerAndSerial,
                sha256Alg,                       // digestAlgorithm
                rsaAlg,                          // digestEncryptionAlgorithm
                encodeOctetString(signature)     // encryptedDigest
        ));

        // SignedData
        byte[] signedData = encodeSequence(concat(
                encodeInteger(BigInteger.ONE),             // version
                encodeSet(sha256Alg),                      // digestAlgorithms
                encodeSequence(encodeOid("1.2.840.113549.1.7.1")), // contentInfo (data)
                encodeTlv(0xA0, certDer),                  // certificates [0]
                encodeSet(signerInfo)                      // signerInfos
        ));

        // ContentInfo
        return encodeSequence(concat(
                encodeOid("1.2.840.113549.1.7.2"),  // signedData OID
                encodeTlv(0xA0, signedData)         // content [0]
        ));
    }

    /**
     * Generates a self-signed X.509 v3 certificate using raw DER encoding
     */
    private X509Certificate generateCert(KeyPair keyPair) throws Exception {
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 365L * 24 * 60 * 60 * 1000);
        Date notAfter = new Date(now + 365L * 10 * 24 * 60 * 60 * 1000);
        BigInteger serial = BigInteger.valueOf(now);
        String issuerStr = "CN=AppCloner Debug";

        byte[] issuerDer = encodeX500Name(issuerStr);
        byte[] validityDer = encodeValidity(notBefore, notAfter);
        byte[] spkiDer = keyPair.getPublic().getEncoded(); // Already full SubjectPublicKeyInfo

        // Version [0] EXPLICIT INTEGER(2) for v3
        byte[] version = encodeTlv(0xA0, encodeInteger(BigInteger.valueOf(2)));
        byte[] serialNum = encodeInteger(serial);
        byte[] sigAlg = encodeSequence(encodeOid("1.2.840.113549.1.1.11")); // SHA256withRSA

        byte[] tbs = encodeSequence(concat(version, serialNum, sigAlg,
                issuerDer, validityDer, issuerDer, spkiDer));

        // Sign TBSCertificate
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(keyPair.getPrivate());
        sig.update(tbs);
        byte[] signatureValue = sig.sign();

        // Certificate
        byte[] certDer = encodeSequence(concat(
                tbs,
                sigAlg,
                encodeBitString(signatureValue)
        ));

        java.security.cert.CertificateFactory cf =
                java.security.cert.CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));
    }

    // --- ASN.1 DER helpers ---

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
        return encodeTlv(0x02, value.toByteArray());
    }

    private byte[] encodeOid(String oid) {
        String[] parts = oid.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(Integer.parseInt(parts[0]) * 40 + Integer.parseInt(parts[1]));
        for (int i = 2; i < parts.length; i++) {
            long v = Long.parseLong(parts[i]);
            if (v < 0x80) {
                out.write((int) v);
            } else {
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
        byte[] content = new byte[data.length + 1];
        content[0] = 0;
        System.arraycopy(data, 0, content, 1, data.length);
        return encodeTlv(0x03, content);
    }

    private byte[] encodeUtf8String(String str) {
        return encodeTlv(0x0C, str.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private byte[] encodeUtcTime(Date date) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US);
        sdf.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        return encodeTlv(0x17, sdf.format(date).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    private byte[] encodeX500Name(String dn) {
        String cn = dn.replace("CN=", "");
        byte[] attrType = encodeOid("2.5.4.3");
        byte[] attrValue = encodeUtf8String(cn);
        byte[] attr = encodeSequence(concat(attrType, attrValue));
        return encodeSequence(encodeSet(attr));
    }

    private byte[] encodeValidity(Date notBefore, Date notAfter) {
        return encodeSequence(concat(encodeUtcTime(notBefore), encodeUtcTime(notAfter)));
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

    // --- Utility methods ---

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

    public File getOutputDir() { return outputDir; }

    public void cleanup() { deleteRecursive(tempDir); }

    private void deleteRecursive(File file) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) deleteRecursive(child);
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
