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
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
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
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * APK cloner using ARSCLib for binary XML modification.
 * Signs APK using standard v1 JAR signing with PKCS12 keystore.
 */
public class ArsclibApkCloner {

    private static final String TAG = "ArsclibApkCloner";
    private Context context;
    private File outputDir;
    private File tempDir;
    private String lastError;
    private KeyPair signingKeyPair;
    private X509Certificate signingCert;

    public ArsclibApkCloner(Context context) {
        this.context = context;
        this.outputDir = new File(context.getExternalFilesDir(null), "cloned");
        this.tempDir = new File(context.getCacheDir(), "temp_clone");

        if (!outputDir.exists()) outputDir.mkdirs();
        if (!tempDir.exists()) tempDir.mkdirs();

        initSigningKey();
    }

    /**
     * Generates and caches a signing key pair + self-signed certificate
     */
    private void initSigningKey() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            signingKeyPair = keyGen.generateKeyPair();
            signingCert = generateCert(signingKeyPair);
            Log.d(TAG, "Signing key initialized: " + signingCert.getSubjectDN());
        } catch (Exception e) {
            Log.e(TAG, "Failed to init signing key", e);
        }
    }

    public ApkMeta getApkMeta(String apkPath) {
        try (ApkFile apkFile = new ApkFile(new File(apkPath))) {
            return apkFile.getApkMeta();
        } catch (IOException e) {
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
        lastError = null;
        try {
            String sourcePath = getApkPath(packageName);
            if (sourcePath == null) {
                lastError = "APK не найден: " + packageName;
                return null;
            }
            Log.d(TAG, "Source: " + sourcePath);

            String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault())
                    .format(new Date());
            String outputName = newPackageName.replaceAll("\\.", "_") + "_" + timestamp + ".apk";
            File unsignedFile = new File(tempDir, "unsigned_" + outputName);
            File signedFile = new File(outputDir, outputName);

            // Step 1: Modify manifest
            byte[] manifestData = extractManifest(sourcePath);
            if (manifestData == null) {
                lastError = "Не удалось извлечь AndroidManifest.xml";
                return null;
            }

            AndroidManifestBlock manifestBlock = new AndroidManifestBlock();
            manifestBlock.readBytes(new ByteArrayInputStream(manifestData));

            String originalPackage = manifestBlock.getPackageName();
            Log.d(TAG, "Package: " + originalPackage + " -> " + newPackageName);

            manifestBlock.setPackageName(newPackageName);
            byte[] modifiedManifest = manifestBlock.getBytes();

            // Step 2: Rebuild without old signature
            if (!rebuildApk(sourcePath, unsignedFile.getAbsolutePath(), modifiedManifest)) {
                lastError = "Ошибка пересборки APK";
                return null;
            }
            Log.d(TAG, "Unsigned APK: " + unsignedFile.length() + " bytes");

            // Step 3: Sign
            if (!signApkV1(unsignedFile.getAbsolutePath(), signedFile.getAbsolutePath())) {
                lastError = "Ошибка подписи APK: " + (lastError != null ? lastError : "unknown");
                return null;
            }
            Log.d(TAG, "Signed APK: " + signedFile.length() + " bytes");

            unsignedFile.delete();
            return signedFile.getAbsolutePath();

        } catch (Exception e) {
            lastError = "Исключение: " + e.getMessage();
            Log.e(TAG, lastError, e);
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

    private boolean rebuildApk(String inputPath, String outputPath, byte[] modifiedManifest) {
        int count = 0;
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(inputPath));
             ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outputPath))) {

            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();

                // Skip old signature
                if (name.startsWith("META-INF/")) continue;

                count++;
                ZipEntry newEntry = new ZipEntry(name);
                newEntry.setMethod(ZipEntry.DEFLATED);
                zos.putNextEntry(newEntry);

                if (name.equals("AndroidManifest.xml")) {
                    zos.write(modifiedManifest);
                } else {
                    byte[] buf = new byte[8192];
                    int len;
                    while ((len = zis.read(buf)) > 0) zos.write(buf, 0, len);
                }
                zos.closeEntry();
            }

            zos.finish();
            Log.d(TAG, "Rebuilt: " + count + " entries");
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Rebuild failed at entry " + count, e);
            lastError = "Rebuild: " + e.getMessage();
            return false;
        }
    }

    /**
     * Signs APK using v1 JAR signing.
     * Builds MANIFEST.MF, CERT.SF, and a minimal PKCS#7 CERT.RSA.
     */
    private boolean signApkV1(String inputPath, String outputPath) {
        try {
            Log.d(TAG, "Signing APK...");

            // Read all entries
            Map<String, byte[]> entries = new HashMap<>();
            try (ZipInputStream zis = new ZipInputStream(new FileInputStream(inputPath))) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    entries.put(entry.getName(), readAllBytes(zis));
                }
            }
            Log.d(TAG, "Entries: " + entries.size());

            // --- MANIFEST.MF ---
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            Manifest manifest = new Manifest();
            Attributes mainAttrs = manifest.getMainAttributes();
            mainAttrs.put(Attributes.Name.MANIFEST_VERSION, "1.0");

            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                Attributes attrs = new Attributes();
                attrs.put(new Attributes.Name("SHA-256-Digest"),
                        android.util.Base64.encodeToString(
                                sha256.digest(e.getValue()), android.util.Base64.NO_WRAP));
                manifest.getEntries().put(e.getKey(), attrs);
            }

            ByteArrayOutputStream manifestBaos = new ByteArrayOutputStream();
            manifest.write(manifestBaos);
            byte[] manifestBytes = manifestBaos.toByteArray();
            Log.d(TAG, "MANIFEST.MF: " + manifestBytes.length + " bytes");

            // --- CERT.SF ---
            StringBuilder sf = new StringBuilder();
            sf.append("Signature-Version: 1.0\r\n");
            sf.append("SHA-256-Digest-Manifest: ");
            sf.append(android.util.Base64.encodeToString(
                    sha256.digest(manifestBytes), android.util.Base64.NO_WRAP));
            sf.append("\r\n\r\n");

            for (Map.Entry<String, Attributes> e : manifest.getEntries().entrySet()) {
                sf.append("Name: ").append(e.getKey()).append("\r\n");
                for (Map.Entry<Object, Object> a : e.getValue().entrySet()) {
                    sf.append(a.getKey()).append(": ").append(a.getValue()).append("\r\n");
                }
                sf.append("\r\n");
            }
            byte[] sfBytes = sf.toString().getBytes("UTF-8");
            Log.d(TAG, "CERT.SF: " + sfBytes.length + " bytes");

            // --- CERT.RSA (PKCS#7) ---
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(signingKeyPair.getPrivate());
            sig.update(sfBytes);
            byte[] sigBytes = sig.sign();

            byte[] certDer = signingCert.getEncoded();
            byte[] pkcs7 = buildPkcs7(sfBytes, sigBytes, certDer);
            Log.d(TAG, "CERT.RSA: " + pkcs7.length + " bytes");

            // --- Write signed APK ---
            try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outputPath))) {
                for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                    ZipEntry ze = new ZipEntry(e.getKey());
                    ze.setMethod(ZipEntry.DEFLATED);
                    zos.putNextEntry(ze);
                    zos.write(e.getValue());
                    zos.closeEntry();
                }

                zos.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
                zos.write(manifestBytes);
                zos.closeEntry();

                zos.putNextEntry(new ZipEntry("META-INF/CERT.SF"));
                zos.write(sfBytes);
                zos.closeEntry();

                zos.putNextEntry(new ZipEntry("META-INF/CERT.RSA"));
                zos.write(pkcs7);
                zos.closeEntry();

                zos.finish();
            }

            File out = new File(outputPath);
            Log.d(TAG, "Signed APK: " + out.length() + " bytes");
            return true;

        } catch (Exception e) {
            lastError = "Sign: " + e.getMessage();
            Log.e(TAG, "Signing failed", e);
            return false;
        }
    }

    /**
     * Builds a minimal PKCS#7 ContentInfo with SignedData.
     * Just enough for Android's v1 signature verification.
     */
    private byte[] buildPkcs7(byte[] content, byte[] signature, byte[] certDer) throws Exception {
        // Digest algorithms SET
        byte[] sha256Oid = encodeOid("2.16.840.1.101.3.4.2.1");
        byte[] digestAlg = encodeSequence(sha256Oid);
        byte[] digestAlgsSet = encodeSet(digestAlg);

        // ContentInfo (empty Data)
        byte[] dataOid = encodeOid("1.2.840.113549.1.7.1");
        byte[] contentInfo = encodeSequence(dataOid);

        // Certificates [0] IMPLICIT
        byte[] certs = encodeTlv(0xA0, certDer);

        // SignerInfo
        byte[] rsaOid = encodeOid("1.2.840.113549.1.1.1");
        byte[] sigAlg = encodeSequence(rsaOid);
        byte[] issuerName = signingCert.getIssuerX500Principal().getEncoded();
        byte[] serial = encodeInteger(signingCert.getSerialNumber());
        byte[] issuerSerial = encodeSequence(concat(issuerName, serial));
        byte[] encDigest = encodeOctetString(signature);

        byte[] signerInfo = encodeSequence(concat(
                encodeInteger(BigInteger.ONE),
                issuerSerial,
                digestAlg,
                sigAlg,
                encDigest
        ));
        byte[] signerInfosSet = encodeSet(signerInfo);

        // SignedData
        byte[] signedData = encodeSequence(concat(
                encodeInteger(BigInteger.ONE),
                digestAlgsSet,
                contentInfo,
                certs,
                signerInfosSet
        ));

        // ContentInfo wrapper
        byte[] signedDataOid = encodeOid("1.2.840.113549.1.7.2");
        return encodeSequence(concat(
                signedDataOid,
                encodeTlv(0xA0, signedData)
        ));
    }

    private X509Certificate generateCert(KeyPair keyPair) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3650L * 86400000L);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        byte[] issuerDer = encodeX500Name("CN=AppCloner");
        byte[] validityDer = encodeSequence(concat(
                encodeUtcTime(notBefore), encodeUtcTime(notAfter)));
        byte[] spkiDer = keyPair.getPublic().getEncoded();

        byte[] tbs = encodeSequence(concat(
                encodeTlv(0xA0, encodeInteger(BigInteger.valueOf(2))),
                encodeInteger(serial),
                encodeSequence(encodeOid("1.2.840.113549.1.1.11")),
                issuerDer, validityDer, issuerDer, spkiDer));

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(keyPair.getPrivate());
        sig.update(tbs);

        byte[] certDer = encodeSequence(concat(
                tbs,
                encodeSequence(encodeOid("1.2.840.113549.1.1.11")),
                encodeBitString(sig.sign())));

        return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certDer));
    }

    // --- ASN.1 helpers ---

    private byte[] encodeSequence(byte[] c) { return encodeTlv(0x30, c); }
    private byte[] encodeSet(byte[] c) { return encodeTlv(0x31, c); }

    private byte[] encodeTlv(int tag, byte[] c) {
        byte[] len = encodeLength(c.length);
        byte[] r = new byte[1 + len.length + c.length];
        r[0] = (byte) tag;
        System.arraycopy(len, 0, r, 1, len.length);
        System.arraycopy(c, 0, r, 1 + len.length, c.length);
        return r;
    }

    private byte[] encodeLength(int len) {
        if (len < 0x80) return new byte[]{(byte) len};
        if (len < 0x100) return new byte[]{(byte) 0x81, (byte) len};
        return new byte[]{(byte) 0x82, (byte) (len >> 8), (byte) len};
    }

    private byte[] encodeInteger(BigInteger v) { return encodeTlv(0x02, v.toByteArray()); }

    private byte[] encodeOid(String oid) {
        String[] p = oid.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(Integer.parseInt(p[0]) * 40 + Integer.parseInt(p[1]));
        for (int i = 2; i < p.length; i++) {
            long v = Long.parseLong(p[i]);
            if (v < 0x80) { out.write((int) v); continue; }
            int[] b = new int[8]; int pos = 0;
            b[pos++] = (int) (v & 0x7F); v >>= 7;
            while (v > 0) { b[pos++] = (int) (v & 0x7F) | 0x80; v >>= 7; }
            for (int j = pos - 1; j >= 0; j--) out.write(b[j]);
        }
        return encodeTlv(0x06, out.toByteArray());
    }

    private byte[] encodeOctetString(byte[] d) { return encodeTlv(0x04, d); }

    private byte[] encodeBitString(byte[] d) {
        byte[] c = new byte[d.length + 1];
        c[0] = 0;
        System.arraycopy(d, 0, c, 1, d.length);
        return encodeTlv(0x03, c);
    }

    private byte[] encodeUtf8String(String s) {
        return encodeTlv(0x0C, s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private byte[] encodeUtcTime(Date d) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US);
        sdf.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        return encodeTlv(0x17, sdf.format(d).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    private byte[] encodeX500Name(String dn) {
        return encodeSequence(encodeSet(encodeSequence(concat(
                encodeOid("2.5.4.3"),
                encodeUtf8String(dn.replace("CN=", ""))))));
    }

    private byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] r = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) { System.arraycopy(a, 0, r, pos, a.length); pos += a.length; }
        return r;
    }

    // --- Public API ---

    public boolean installApk(String apkPath) {
        try {
            File f = new File(apkPath);
            if (!f.exists()) return false;
            Uri uri = Build.VERSION.SDK_INT >= Build.VERSION_CODES.N
                    ? FileProvider.getUriForFile(context, context.getPackageName() + ".provider", f)
                    : Uri.fromFile(f);
            Intent intent = new Intent(Intent.ACTION_VIEW);
            intent.setDataAndType(uri, "application/vnd.android.package-archive");
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_GRANT_READ_URI_PERMISSION);
            context.startActivity(intent);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Install error", e);
            return false;
        }
    }

    public boolean shareApk(String apkPath) {
        try {
            File f = new File(apkPath);
            if (!f.exists()) return false;
            Uri uri = Build.VERSION.SDK_INT >= Build.VERSION_CODES.N
                    ? FileProvider.getUriForFile(context, context.getPackageName() + ".provider", f)
                    : Uri.fromFile(f);
            Intent i = new Intent(Intent.ACTION_SEND);
            i.setType("application/vnd.android.package-archive");
            i.putExtra(Intent.EXTRA_STREAM, uri);
            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            context.startActivity(Intent.createChooser(i, "Share APK"));
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Share error", e);
            return false;
        }
    }

    public File getOutputDir() { return outputDir; }
    public String getLastError() { return lastError; }
    public void cleanup() { deleteRecursive(tempDir); }

    private void deleteRecursive(File f) {
        if (f.isDirectory()) {
            File[] c = f.listFiles();
            if (c != null) for (File child : c) deleteRecursive(child);
        }
        f.delete();
    }

    private byte[] readAllBytes(InputStream is) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] data = new byte[8192];
        int len;
        while ((len = is.read(data)) != -1) buf.write(data, 0, len);
        return buf.toByteArray();
    }
}
