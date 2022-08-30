/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Based on SignApk from Android:
// https://android.googlesource.com/platform/build/+/android-6.0.0_r26/tools/signapk/SignApk.java
// Modifications for SignServer:
// - Made helper methods visible outside of the class in order to call them from our code
// - Added Provider argument to the methods instead of the static Provider
// - Added DSA key and signature algorithm support
// - Optional: Removed main method as we don't use it
// - Added argument for explicitly specify which signature algorithm to use
// - Added argument for explicitly specify which digest algorithm to use
// - Added time-stamping support
// - Added support for adding additional signatures
// - Added support for specifying signature file name
// - Added support for certificate chains
// - Added support for specifying a created-by string
// - Fixed NPE when an Name attribute does not exist (or is an URL)
// - Changed methods to not declare they throw raw Exception type

package org.signserver.module.jarchive.impl.signapk;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;
import java.io.Console;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.DigestOutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.signserver.common.IllegalRequestException;
/**
 * HISTORICAL NOTE:
 *
 * Prior to the keylimepie release, SignApk ignored the signature
 * algorithm specified in the certificate and always used SHA1withRSA.
 *
 * Starting with JB-MR2, the platform supports SHA256withRSA, so we use
 * the signature algorithm in the certificate to select which to use
 * (SHA256withRSA or SHA1withRSA). Also in JB-MR2, EC keys are supported.
 *
 * Because there are old keys still in use whose certificate actually
 * says "MD5withRSA", we treat these as though they say "SHA1withRSA"
 * for compatibility with older releases.  This can be changed by
 * altering the getAlgorithm() function below.
 */

/**
 * Command line tool to sign JAR files (including APKs and OTA updates) in a way
 * compatible with the mincrypt verifier, using EC or RSA keys and SHA1 or
 * SHA-256 (see historical note).
 */
class SignApk {
    private static final String OTACERT_NAME = "META-INF/com/android/otacert";
    // bitmasks for which hash algorithms we need the manifest to include.
    private static final int USE_SHA1 = 1;
    private static final int USE_SHA256 = 2;
    /**
     * Return one of USE_SHA1 or USE_SHA256 according to the signature
     * algorithm specified in the cert.
     */
    static int getDigestAlgorithm(X509Certificate cert) {
        String sigAlg = cert.getSigAlgName().toUpperCase(Locale.US);
        if ("SHA1WITHRSA".equals(sigAlg) ||
            "MD5WITHRSA".equals(sigAlg)) {     // see "HISTORICAL NOTE" above.
            return USE_SHA1;
        } else if (sigAlg.startsWith("SHA256WITH")) {
            return USE_SHA256;
        } else {
            throw new IllegalArgumentException("unsupported signature algorithm \"" + sigAlg +
                                               "\" in cert [" + cert.getSubjectDN());
        }
    }
    /** Returns the expected signature algorithm for this key type. */
    private static String getSignatureAlgorithm(X509Certificate cert) {
        String keyType = cert.getPublicKey().getAlgorithm().toUpperCase(Locale.US);
        if ("RSA".equalsIgnoreCase(keyType)) {
            if (getDigestAlgorithm(cert) == USE_SHA256) {
                return "SHA256withRSA";
            } else {
                return "SHA1withRSA";
            }
        } else if ("EC".equalsIgnoreCase(keyType)) {
            return "SHA256withECDSA";
        } else if ("DSA".equalsIgnoreCase(keyType)) {
            if (getDigestAlgorithm(cert) == USE_SHA256) {
                return "SHA256withDSA";
            } else {
                return "SHA1withDSA";
            }
        } else {
            throw new IllegalArgumentException("unsupported key type: " + keyType);
        }
    }
    // Files matching this pattern are not copied to the output.
    private static final Pattern STRIP_PATTERN =
        Pattern.compile("^(META-INF/((.*)[.](SF|RSA|DSA|EC)|com/android/otacert))|(" +
                        Pattern.quote(JarFile.MANIFEST_NAME) + ")$");
    private static final Pattern STRIP_PATTERN_NO_MANIFEST =
        Pattern.compile("^(META-INF/((.*)[.](SF|RSA|DSA|EC)|com/android/otacert))$");
    public static final String SIGNAPK_VERSION = "1.0 (Android SignApk)";

    /**
     * Reads the password from console and returns it as a string.
     *
     * @param keyFile The file containing the private key.  Used to prompt the user.
     */
    private static String readPassword(File keyFile) {
        Console console;
        char[] pwd;
        if((console = System.console()) != null &&
           (pwd = console.readPassword("[%s]", "Enter password for " + keyFile)) != null){
            return String.valueOf(pwd);
        } else {
            return null;
        }
    }
    /**
     * Decrypt an encrypted PKCS#8 format private key.
     *
     * Based on ghstark's post on Aug 6, 2006 at
     * http://forums.sun.com/thread.jspa?threadID=758133&messageID=4330949
     *
     * @param encryptedPrivateKey The raw data of the private key
     * @param keyFile The file containing the private key
     */
    private static PKCS8EncodedKeySpec decryptPrivateKey(byte[] encryptedPrivateKey, File keyFile)
        throws GeneralSecurityException {
        EncryptedPrivateKeyInfo epkInfo;
        try {
            epkInfo = new EncryptedPrivateKeyInfo(encryptedPrivateKey);
        } catch (IOException ex) {
            // Probably not an encrypted key.
            return null;
        }
        char[] password = readPassword(keyFile).toCharArray();
        SecretKeyFactory skFactory = SecretKeyFactory.getInstance(epkInfo.getAlgName());
        Key key = skFactory.generateSecret(new PBEKeySpec(password));
        Cipher cipher = Cipher.getInstance(epkInfo.getAlgName());
        cipher.init(Cipher.DECRYPT_MODE, key, epkInfo.getAlgParameters());
        try {
            return epkInfo.getKeySpec(cipher);
        } catch (InvalidKeySpecException ex) {
            System.err.println("signapk: Password for " + keyFile + " may be bad.");
            throw ex;
        }
    }
    /**
     * Add the hash(es) of every file to the manifest, creating it if
     * necessary.
     */
    static Manifest addDigestsToManifest(JarFile jar, List<String> hashes, String createdBy)
        throws IOException, GeneralSecurityException {
        Manifest input = jar.getManifest();
        Manifest output = jar.getManifest(); //new Manifest();
        if (output == null) {
            output = new Manifest();
            Attributes main = output.getMainAttributes();
            main.putValue("Manifest-Version", "1.0");
            main.putValue("Created-By", createdBy);
        }
        
        // Create each MessageDigest
        final List<MessageDigest> mds = new ArrayList<>();
        for (String hash : hashes) {
            mds.add(MessageDigest.getInstance(hash, BouncyCastleProvider.PROVIDER_NAME));
        }
        
        byte[] buffer = new byte[4096];
        int num;
        // We sort the input entries by name, and add them to the
        // output manifest in sorted order.  We expect that the output
        // map will be deterministic.
        TreeMap<String, JarEntry> byName = new TreeMap<>();
        for (Enumeration<JarEntry> e = jar.entries(); e.hasMoreElements(); ) {
            JarEntry entry = e.nextElement();
            byName.put(entry.getName(), entry);
        }
        for (JarEntry entry: byName.values()) {
            String name = entry.getName();
            if (!entry.isDirectory() && !STRIP_PATTERN.matcher(name).matches()) {
                InputStream data = jar.getInputStream(entry);
                while ((num = data.read(buffer)) > 0) {
                    for (MessageDigest md : mds) {
                        md.update(buffer, 0, num);
                    }
                }
                Attributes attr = null;
                if (input != null) {
                    attr = input.getAttributes(name);
                }
                attr = attr != null ? new Attributes(attr) : new Attributes();
                
                // Add each digest
                for (int i = 0; i < hashes.size(); i++) {
                    attr.putValue(hashes.get(i) + "-Digest",
                                  new String(Base64.encode(mds.get(i).digest()), "ASCII"));
                }
                
                output.getEntries().put(name, attr);
            }
        }
        return output;
    }
    /**
     * Add a copy of the public key to the archive; this should
     * exactly match one of the files in
     * /system/etc/security/otacerts.zip on the device.  (The same
     * cert can be extracted from the CERT.RSA file but this is much
     * easier to get at.)
     */
    private static void addOtacert(JarOutputStream outputJar,
                                   File publicKeyFile,
                                   long timestamp,
                                   Manifest manifest,
                                   int hash)
        throws IOException, GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance(hash == USE_SHA1 ? "SHA1" : "SHA256", BouncyCastleProvider.PROVIDER_NAME);
        JarEntry je = new JarEntry(OTACERT_NAME);
        je.setTime(timestamp);
        outputJar.putNextEntry(je);
        try (FileInputStream input = new FileInputStream(publicKeyFile)) {
            byte[] b = new byte[4096];
            int read;
            while ((read = input.read(b)) != -1) {
                outputJar.write(b, 0, read);
                md.update(b, 0, read);
            }
        }
        Attributes attr = new Attributes();
        attr.putValue(hash == USE_SHA1 ? "SHA1-Digest" : "SHA-256-Digest",
                      new String(Base64.encode(md.digest()), "ASCII"));
        manifest.getEntries().put(OTACERT_NAME, attr);
    }
    /** Write to another stream and track how many bytes have been
     *  written.
     */
    private static class CountOutputStream extends FilterOutputStream {
        private int mCount;
        public CountOutputStream(OutputStream out) {
            super(out);
            mCount = 0;
        }
        @Override
        public void write(int b) throws IOException {
            super.write(b);
            mCount++;
        }
        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            super.write(b, off, len);
            mCount += len;
        }
        public int size() {
            return mCount;
        }
    }
    /** Write a .SF file with a digest of the specified manifest. */
    static void writeSignatureFile(Manifest manifest, OutputStream out,
                                           String digestAlgorithm, String createdBy)
        throws IOException, GeneralSecurityException {
        Manifest sf = new Manifest();
        Attributes main = sf.getMainAttributes();
        main.putValue("Signature-Version", "1.0");
        main.putValue("Created-By", createdBy);

        MessageDigest md = MessageDigest.getInstance(digestAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
        PrintStream print = new PrintStream(
            new DigestOutputStream(new ByteArrayOutputStream(), md),
            true, StandardCharsets.UTF_8.name());
        // Digest of the entire manifest
        manifest.write(print);
        print.flush();
        main.putValue(digestAlgorithm + "-Digest-Manifest",
                      new String(Base64.encode(md.digest()), "ASCII"));
        Map<String, Attributes> entries = manifest.getEntries();
        for (Map.Entry<String, Attributes> entry : entries.entrySet()) {
            // Digest of the manifest stanza for this entry.
            // Note: "Line length:
            //    No line may be longer than 72 bytes (not characters), in its UTF8-encoded form. If a value would make the initial line longer than this, it should be continued on extra lines (each starting with a single SPACE).
            // https://docs.oracle.com/en/java/javase/17/docs/specs/jar/jar.html#signature-file

            byte[] nameName = "Name: ".getBytes(StandardCharsets.UTF_8);
            print.write(nameName);
            int written = nameName.length;

            char[] nameChars = entry.getKey().toCharArray();

            for (int i = 0; i < nameChars.length; i++) {
                byte[] ch = String.valueOf(nameChars[i]).getBytes(StandardCharsets.UTF_8);

                if (written + ch.length > 72) {
                    print.print("\r\n "); // Note: CR LF SPACE
                    written = 1;
                }
                print.write(ch);
                written += ch.length;
            }
            print.print("\r\n");

            for (Map.Entry<Object, Object> att : entry.getValue().entrySet()) {
                print.print(att.getKey() + ": " + att.getValue() + "\r\n");
            }
            print.print("\r\n");
            print.flush();
            Attributes sfAttr = new Attributes();
            sfAttr.putValue(digestAlgorithm + "-Digest",
                            new String(Base64.encode(md.digest()), "ASCII"));
            sf.getEntries().put(entry.getKey(), sfAttr);
        }
        CountOutputStream cout = new CountOutputStream(out);
        sf.write(cout);
        // A bug in the java.util.jar implementation of Android platforms
        // up to version 1.6 will cause a spurious IOException to be thrown
        // if the length of the signature file is a multiple of 1024 bytes.
        // As a workaround, add an extra CRLF in this case.
        if ((cout.size() % 1024) == 0) {
            cout.write('\r');
            cout.write('\n');
        }
    }
    /** Sign data and write the digital signature to 'out'. */
    private static void writeSignatureBlock(
        CMSTypedData data, X509Certificate[] certificateChain, PrivateKey privateKey, Provider signerProvider,
        OutputStream out, String signatureAlgorithm, TimeStampingProvider timeStamping)
        throws IOException,
               CertificateEncodingException,
               OperatorCreationException,
               CMSException {
        ArrayList<X509Certificate> certList = new ArrayList<>(1);
        certList.addAll(Arrays.<X509Certificate>asList(certificateChain));
        JcaCertStore certs = new JcaCertStore(certList);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm != null ? signatureAlgorithm : getSignatureAlgorithm(certificateChain[0]))
            .setProvider(signerProvider)
            .build(privateKey);
        gen.addSignerInfoGenerator(
            new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder()
                .setProvider("BC") // Use BouncyCastle for the digest calculation
                .build())
            .setDirectSignature(true)
            .build(signer, certificateChain[0]));
        gen.addCertificates(certs);
        CMSSignedData sigData = gen.generate(data, false);
        if (timeStamping != null) {
            sigData = timeStamping.timestamp(sigData);
        }
        ASN1InputStream asn1 = new ASN1InputStream(sigData.getEncoded());
        ASN1OutputStream dos = ASN1OutputStream.create(out, ASN1Encoding.DER);
        dos.writeObject(asn1.readObject());
    }
    /**
     * Copy all the files in a manifest from input to output.  We set
     * the modification times in the output to a fixed time, so as to
     * reduce variation in the output file and make incremental OTAs
     * more efficient.
     */
    static void copyFiles(long offset, Manifest manifest, JarFile in, JarOutputStream out,
                                  long timestamp, int alignment, boolean keepSignatures, boolean replaceSignature, String signatureName) throws IOException, IllegalRequestException {
        byte[] buffer = new byte[4096];
        int num;
        // We do the copy in two passes -- first copying all the
        // entries that are STORED, then copying all the entries that
        // have any other compression flag (which in practice means
        // DEFLATED).  This groups all the stored entries together at
        // the start of the file and makes it easier to do alignment
        // on them (since only stored entries are aligned).
        Enumeration<JarEntry> inEntries = in.entries();

        final String sfName = createSFName(1, 0, signatureName);
        
        while (inEntries.hasMoreElements()) {
            JarEntry inEntry = inEntries.nextElement();
            JarEntry outEntry = null;
            if (inEntry == null || inEntry.getMethod() != JarEntry.STORED ||
                "META-INF/".equals(inEntry.getName()) ||
                "META-INF/MANIFEST.MF".equals(inEntry.getName())) { // We have explicitly added META-INF/ and META-INF/MANIFEST.MF before
                continue;
            } else {
                final String name = inEntry.getName();
                if (replaceSignature && (sfName.equalsIgnoreCase(name)
                            || (name.startsWith(createKeyBaseName(1, 0, signatureName)) && (name.endsWith("RSA") || name.endsWith("DSA") || name.endsWith("EC"))))) {
                    continue;
                } else if (!replaceSignature && sfName.equalsIgnoreCase(name)) {
                    throw new IllegalRequestException("Already signed with same name: " + signatureName);
                } else if (!keepSignatures && STRIP_PATTERN_NO_MANIFEST.matcher(name).matches()) {
                    continue;
                }
            }

            // Preserve the STORED method of the input entry.
            outEntry = new JarEntry(inEntry);
            if (timestamp != -1) {
                outEntry.setTime(timestamp);
            }
            // 'offset' is the offset into the file at which we expect
            // the file data to begin.  This is the value we need to
            // make a multiple of 'alignement'.
            offset += JarFile.LOCHDR + outEntry.getName().length();

            if (alignment > 0 && (offset % alignment != 0)) {
                // Set the "extra data" of the entry to between 1 and
                // alignment-1 bytes, to make the file data begin at
                // an aligned offset.
                int needed = alignment - (int)(offset % alignment);
                outEntry.setExtra(new byte[needed]);
                offset += needed;
            }
            out.putNextEntry(outEntry);
            InputStream data = in.getInputStream(inEntry);
            while ((num = data.read(buffer)) > 0) {
                out.write(buffer, 0, num);
                offset += num;
            }
            out.flush();
        }
        // Copy all the non-STORED entries.  We don't attempt to
        // maintain the 'offset' variable past this point; we don't do
        // alignment on these entries.
        inEntries = in.entries();
        while (inEntries.hasMoreElements()) {
            JarEntry inEntry = inEntries.nextElement();
            JarEntry outEntry = null;
            if (inEntry == null || inEntry.getMethod() == JarEntry.STORED || "META-INF/".equals(inEntry.getName()) || "META-INF/MANIFEST.MF".equals(inEntry.getName())) { // We have explicitly added META-INF/ before
                continue;
            } else {
                final String name = inEntry.getName();
                if (replaceSignature && (sfName.equalsIgnoreCase(name)
                            || (name.startsWith(createKeyBaseName(1, 0, signatureName)) && (name.endsWith("RSA") || name.endsWith("DSA") || name.endsWith("EC"))))) {
                    continue;
                } else if (!replaceSignature && sfName.equalsIgnoreCase(name)) {
                    throw new IllegalRequestException("Already signed with same name: " + signatureName);
                } else if (!keepSignatures && STRIP_PATTERN_NO_MANIFEST.matcher(name).matches()) {
                    continue;
                }
            }
            // Create a new entry so that the compressed len is recomputed.
            outEntry = new JarEntry(inEntry.getName());
            if (timestamp != -1) {
                outEntry.setTime(timestamp);
            }
            out.putNextEntry(outEntry);
            InputStream data = in.getInputStream(inEntry);
            while ((num = data.read(buffer)) > 0) {
                out.write(buffer, 0, num);
            }
            out.flush();
        }
    }
    private static class WholeFileSignerOutputStream extends FilterOutputStream {
        private boolean closing = false;
        private ByteArrayOutputStream footer = new ByteArrayOutputStream();
        private OutputStream tee;
        public WholeFileSignerOutputStream(OutputStream out, OutputStream tee) {
            super(out);
            this.tee = tee;
        }
        public void notifyClosing() {
            closing = true;
        }
        public void finish() throws IOException {
            closing = false;
            byte[] data = footer.toByteArray();
            if (data.length < 2) {
                throw new IOException("Less than two bytes written to footer");
            }
            write(data, 0, data.length - 2);
        }
        public byte[] getTail() {
            return footer.toByteArray();
        }
        @Override
        public void write(byte[] b) throws IOException {
            write(b, 0, b.length);
        }
        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (closing) {
                // if the jar is about to close, save the footer that will be written
                footer.write(b, off, len);
            }
            else {
                // write to both output streams. out is the CMSTypedData signer and tee is the file.
                out.write(b, off, len);
                tee.write(b, off, len);
            }
        }
        @Override
        public void write(int b) throws IOException {
            if (closing) {
                // if the jar is about to close, save the footer that will be written
                footer.write(b);
            }
            else {
                // write to both output streams. out is the CMSTypedData signer and tee is the file.
                out.write(b);
                tee.write(b);
            }
        }
    }
    private static class CMSSigner implements CMSTypedData {
        private JarFile inputJar;
        private File publicKeyFile;
        private X509Certificate[] certificateChain;
        private PrivateKey privateKey;
        private Provider provider;
        private OutputStream outputStream;
        private final ASN1ObjectIdentifier type;
        private WholeFileSignerOutputStream signer;
        private final String signatureAlgorithm;
        private final String digestAlgorithm;
        private final TimeStampingProvider timeStamping;
        private final boolean keepSignatures;
        private final boolean replaceSignature;
        private final String signatureName;
        private final String createdBy;
        public CMSSigner(JarFile inputJar, File publicKeyFile,
                         X509Certificate[] certificateChain, PrivateKey privateKey,
                         Provider provider,
                         OutputStream outputStream, String signatureAlgorithm, String digestAlgorithm, TimeStampingProvider timeStamping, boolean keepSignatures, boolean replaceSignature, String signatureName, String createdBy) {
            this.inputJar = inputJar;
            this.publicKeyFile = publicKeyFile;
            this.certificateChain = certificateChain;
            this.privateKey = privateKey;
            this.provider = provider;
            this.outputStream = outputStream;
            this.type = new ASN1ObjectIdentifier(CMSObjectIdentifiers.data.getId());
            this.signatureAlgorithm = signatureAlgorithm;
            this.digestAlgorithm = digestAlgorithm;
            this.timeStamping = timeStamping;
            this.keepSignatures = keepSignatures;
            this.replaceSignature = replaceSignature;
            this.signatureName = signatureName;
            this.createdBy = createdBy;
        }
        /**
         * This should actually return byte[] or something similar, but nothing
         * actually checks it currently.
         */
        @Override
        public Object getContent() {
            return this;
        }
        @Override
        public ASN1ObjectIdentifier getContentType() {
            return type;
        }
        @Override
        public void write(OutputStream out) throws IOException {
            try {
                signer = new WholeFileSignerOutputStream(out, outputStream);
                try (JarOutputStream outputJar = new JarOutputStream(signer)) {
                    int hash = getDigestAlgorithm(certificateChain[0]);
                    // Assume the certificate is valid for at least an hour.
                    long timestamp = certificateChain[0].getNotBefore().getTime() + 3600L * 1000;
                    Manifest manifest = addDigestsToManifest(inputJar, Arrays.<String>asList(digestAlgorithm != null ? digestAlgorithm : (getDigestAlgorithm(certificateChain[0]) == USE_SHA256 ? "SHA-256" : "SHA1")), createdBy);
                    copyFiles(0, manifest, inputJar, outputJar, timestamp, 0, keepSignatures, replaceSignature, signatureName);
                    addOtacert(outputJar, publicKeyFile, timestamp, manifest, hash);
                    if (true) {
                        throw new UnsupportedOperationException("TODO: signFile modified to not write the signature. Handle here!"); // TODO !!!!!
                    }
                    // for now just add a dummy 0 alignment argument, but this is never called...
                    signFile(manifest, inputJar,
                            new X509Certificate[][]{ certificateChain },
                            new PrivateKey[]{ privateKey },
                            provider,
                            outputJar,
                            signatureAlgorithm,
                            digestAlgorithm,
                            timeStamping,
                            keepSignatures,
                            signatureName,
                            createdBy);
                    signer.notifyClosing();
                }
                signer.finish();
            }
            catch (Exception e) {
                throw new IOException(e);
            }
        }
        public void writeSignatureBlock(ByteArrayOutputStream temp)
            throws IOException,
                   CertificateEncodingException,
                   OperatorCreationException,
                   CMSException {
            SignApk.writeSignatureBlock(this, certificateChain, privateKey, provider, temp, signatureAlgorithm, timeStamping);
        }
        public WholeFileSignerOutputStream getSigner() {
            return signer;
        }
    }
    /** Provider of the timestamps. */
    public static interface TimeStampingProvider {
        
        CMSSignedData timestamp(CMSSignedData cms) throws IOException;
    }
    static void signWholeFile(JarFile inputJar, File publicKeyFile,
                                      X509Certificate[] certificateChain, PrivateKey privateKey,
                                      Provider provider,
                                      OutputStream outputStream, String signatureAlgorithm, String digestAlgorithm, TimeStampingProvider timeStamping, boolean keepSignatures, boolean replaceSignature, String signatureName, String createdBy) throws IOException, CertificateEncodingException, OperatorCreationException, CMSException {
        CMSSigner cmsOut = new CMSSigner(inputJar, publicKeyFile,
                                         certificateChain, privateKey, provider, outputStream, signatureAlgorithm, digestAlgorithm, timeStamping, keepSignatures, replaceSignature, signatureName, createdBy);
        ByteArrayOutputStream temp = new ByteArrayOutputStream();
        // put a readable message and a null char at the start of the
        // archive comment, so that tools that display the comment
        // (hopefully) show something sensible.
        // TODO: anything more useful we can put in this message?
        byte[] message = "signed by SignApk".getBytes(StandardCharsets.UTF_8);
        temp.write(message);
        temp.write(0);
        cmsOut.writeSignatureBlock(temp);
        byte[] zipData = cmsOut.getSigner().getTail();
        // For a zip with no archive comment, the
        // end-of-central-directory record will be 22 bytes long, so
        // we expect to find the EOCD marker 22 bytes from the end.
        if (zipData[zipData.length-22] != 0x50 ||
            zipData[zipData.length-21] != 0x4b ||
            zipData[zipData.length-20] != 0x05 ||
            zipData[zipData.length-19] != 0x06) {
            throw new IllegalArgumentException("zip data already has an archive comment");
        }
        int total_size = temp.size() + 6;
        if (total_size > 0xffff) {
            throw new IllegalArgumentException("signature is too big for ZIP file comment");
        }
        // signature starts this many bytes from the end of the file
        int signature_start = total_size - message.length - 1;
        temp.write(signature_start & 0xff);
        temp.write((signature_start >> 8) & 0xff);
        // Why the 0xff bytes?  In a zip file with no archive comment,
        // bytes [-6:-2] of the file are the little-endian offset from
        // the start of the file to the central directory.  So for the
        // two high bytes to be 0xff 0xff, the archive would have to
        // be nearly 4GB in size.  So it's unlikely that a real
        // commentless archive would have 0xffs here, and lets us tell
        // an old signed archive from a new one.
        temp.write(0xff);
        temp.write(0xff);
        temp.write(total_size & 0xff);
        temp.write((total_size >> 8) & 0xff);
        temp.flush();
        // Signature verification checks that the EOCD header is the
        // last such sequence in the file (to avoid minzip finding a
        // fake EOCD appended after the signature in its scan).  The
        // odds of producing this sequence by chance are very low, but
        // let's catch it here if it does.
        byte[] b = temp.toByteArray();
        for (int i = 0; i < b.length-3; ++i) {
            if (b[i] == 0x50 && b[i+1] == 0x4b && b[i+2] == 0x05 && b[i+3] == 0x06) {
                throw new IllegalArgumentException("found spurious EOCD header at " + i);
            }
        }
        outputStream.write(total_size & 0xff);
        outputStream.write((total_size >> 8) & 0xff);
        temp.writeTo(outputStream);
    }
    static void signFile(Manifest manifest, JarFile inputJar,
                                 X509Certificate[][] certificateChains, PrivateKey[] privateKey,
                                 Provider provider,
                                 JarOutputStream outputJar,
                                 String signatureAlgorithm,
                                 String digestAlgorithm,
                                 TimeStampingProvider timeStamping,
                                 boolean keepSignatures,
                                 String signatureName, String createdBy)
            throws IOException, GeneralSecurityException,
                   CertificateEncodingException, OperatorCreationException,
                   CMSException
         {
        // Assume the certificate is valid for at least an hour.
        long timestamp = certificateChains[0][0].getNotBefore().getTime() + 3600L * 1000;

        int numKeys = certificateChains.length;
        for (int k = 0; k < numKeys; ++k) {
            // CERT.SF / CERT#.SF
            JarEntry je = new JarEntry(createSFName(numKeys, k, signatureName));
            je.setTime(timestamp);
            outputJar.putNextEntry(je);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            String digestAlg = digestAlgorithm;
            if (digestAlg == null) {
                digestAlg = (getDigestAlgorithm(certificateChains[k][0]) == USE_SHA256) ? "SHA-256" : "SHA1";
            }
            writeSignatureFile(manifest, baos, digestAlg, createdBy);
            byte[] signedData = baos.toByteArray();
            outputJar.write(signedData);
            // CERT.{EC,RSA} / CERT#.{EC,RSA}
            final String keyType = certificateChains[k][0].getPublicKey().getAlgorithm();
            je = new JarEntry(createKeyBaseName(numKeys, k, signatureName) + keyType);
            je.setTime(timestamp);
            outputJar.putNextEntry(je);
            writeSignatureBlock(new CMSProcessableByteArray(signedData),
                                certificateChains[k], privateKey[k], provider, outputJar, signatureAlgorithm, timeStamping);
        }
    }
    
    private static String createSFName(int numKeys, int k, String signatureName) {
        return "META-INF/" + (numKeys == 1 ? signatureName : signatureName + String.valueOf(k)) + ".SF";
    }
    
    private static String createKeyBaseName(int numKeys, int k, String signatureName) {
        return "META-INF/" + signatureName + (numKeys > 1 ? String.valueOf(k) : "" + ".");
    }

}
