/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.jarchive.signer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.CodeSigner;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Objects;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.naming.NamingException;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.fail;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.NullOutputStream;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.selector.jcajce.JcaX509CertificateHolderSelector;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.cli.CommandLineInterface;
import org.signserver.client.cli.ClientCLI;
import org.signserver.common.ServiceLocator;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.data.ReadableData;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;

/**
 * System tests for the client-side hashing specific uses of JAR signing.
 *
 * This tests requires a running SignServer.
 * 
 * This test cases are mostly to cover the parameters provided on the client-side
 * for how to create the JAR signature. For the server-side case this is covered
 * in the JArchiveSignerUnitTest.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class JArchiveClientSideTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(JArchiveSignerTest.class);

    private static final int WORKER_ID_CLIENTSIDE = 8907;
    private static final String WORKER_NAME_CLIENTSIDE = "TestJArchiveCMSSigner";

    //JDK8: private static final ASN1ObjectIdentifier ID_SHA1WITHDSA = new ASN1ObjectIdentifier("1.2.840.10040.4.3");
    //JDK8: private static final ASN1ObjectIdentifier ID_SHA256WITHDSA = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.2");
    private static final String JAVA_SHA_512 = "SHA-512";
    private static final String JAVA_SHA_256 = "SHA-256";
    private static final String JAVA_SHA1 = "SHA1";
    private static final String KEYALIAS_REAL = "Key alias 1";
    private static final String KEYALIAS_CONVERTED = "KEY_ALIA";
    
    private final File executableFile;
    
    /** File HelloJar-signed.jar containing CERT0.SF and CERT0.RSA using SHA-256 digest. */
    private static File executableFileWithSignature;

    /** File HelloJar-signed-ts.jar containing CERT.SF and CERT.RSA, using SHA-256 digest and with a time-stamp. */
    private static File executableFileWithSignatureTS;
    
    private static WorkerSessionRemote workerSession = getWorkerSessionS();
    private static ProcessSessionRemote processSession = getProcessSessionS();

    private static final CLITestHelper cli = new CLITestHelper(ClientCLI.class);

    private final ModulesTestCase helper = new ModulesTestCase();
    
    public JArchiveClientSideTest() throws Exception {
        // Sample binaries to test with
        executableFile = new File(PathUtil.getAppHome(), "lib/SignServer-ejb.jar");
        if (!executableFile.exists()) {
            throw new Exception("Missing sample binary: " + executableFile);
        }
        executableFileWithSignature = new File(PathUtil.getAppHome(), "res/test/HelloJar-signed.jar");
        if (!executableFileWithSignature.exists()) {
            throw new Exception("Missing sample binary: " + executableFileWithSignature);
        }
        executableFileWithSignatureTS = new File(PathUtil.getAppHome(), "res/test/HelloJar-signed-ts.jar");
        if (!executableFileWithSignatureTS.exists()) {
            throw new Exception("Missing sample binary: " + executableFileWithSignatureTS);
        }
    }
    
    protected static WorkerSessionRemote getWorkerSessionS() {
        if (workerSession == null) {
            try {
                workerSession = ServiceLocator.getInstance().lookupRemote(
                    WorkerSessionRemote.class);
            } catch (NamingException ex) {
                fail("Could not lookup WorkerSession: " + ex.getMessage());
            }
        }
        return workerSession;
    }
    
    protected static ProcessSessionRemote getProcessSessionS() {
        if (processSession == null) {
            try {
                processSession = ServiceLocator.getInstance().lookupRemote(
                    ProcessSessionRemote.class);
            } catch (NamingException ex) {
                fail("Could not lookup WorkerSession: " + ex.getMessage());
            }
        }
        return processSession;
    }

    private void addSigner() throws Exception {
        helper.addJArchiveCMSSigner(WORKER_ID_CLIENTSIDE, WORKER_NAME_CLIENTSIDE, true);
        workerSession.setWorkerProperty(WORKER_ID_CLIENTSIDE, "SIGNATUREALGORITHM", "SHA256withRSA");
    }

    /**
     * Test signing when explicitly specified the "SHA1" digest algorithm.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_digestSHA1() throws Exception {
        LOG.info("testNormalSigning_digestSHA1");
        try {
            addSigner();
            workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
            signAndAssertOk(WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA1" }, 
                    JAVA_SHA1, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
        } finally {
            helper.removeWorker(WORKER_ID_CLIENTSIDE);
        }
    }
    
    /**
     * Test signing when explicitly specified the "SHA-1" digest algorithm.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_digestSHA_1() throws Exception {
        LOG.info("testNormalSigning_digestSHA_1");
        try {
            addSigner();
            workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
            signAndAssertOk(WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-1" }, 
                    JAVA_SHA1, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
        } finally {
            helper.removeWorker(WORKER_ID_CLIENTSIDE);
        }
    }

    /**
     * Test signing when specified the SHA-256 digest algorithm.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_digestSHA256() throws Exception {
        LOG.info("testNormalSigning_digestSHA256");
        try {
            addSigner();
            workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
            signAndAssertOk(WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-256" }, 
                    JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
        } finally {
            helper.removeWorker(WORKER_ID_CLIENTSIDE);
        }
    }

    /**
     * Test signing when specified the SHA-512 digest algorithm but SHA1WithRSA.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_digestSHA512() throws Exception {
        LOG.info("testNormalSigning_digestSHA256");
        try {
            addSigner();
            workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
            signAndAssertOk(WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-512" }, 
                    JAVA_SHA_512, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
        } finally {
            helper.removeWorker(WORKER_ID_CLIENTSIDE);
        }
    }

    /**
     * Test signing of a normal ZIP file (one without META-INF/MANIFEST.MF).
     * @throws Exception
     */
    @Test
    public void testSignZIP() throws Exception {
        LOG.info("testSignZIP");

        // Create a ZIP file
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        ZipOutputStream out = new ZipOutputStream(bout);
        ZipEntry entry = new ZipEntry("file1.txt");
        out.putNextEntry(entry);
        out.write("Content of file 1.".getBytes("ASCII"));
        out.closeEntry();
        out.finish();

        final byte[] data = bout.toByteArray();
                
        try {
            addSigner();
            workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
            signAndAssertOk(data, WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-512" }, 
                    JAVA_SHA_512, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
        } finally {
            helper.removeWorker(WORKER_ID_CLIENTSIDE);
        }
    }

    /**
     * Tests that setting an incorrect value for ZIPALIGN gives an error.
     * @throws Exception
     */
    @Test
    public void testOption_incorrectZipAlign() throws Exception {
        LOG.info("testOption_incorrectZipAlign");
        try {
            addSigner();
            workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
            signAndAssert(-2, FileUtils.readFileToByteArray(executableFile), WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-256", 
                "-extraoption", "ZIPALIGN=_INCORRECT_VALUE_"}, 
                    JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, Collections.<Certificate>emptyList(), Collections.<WrappedJarEntry>emptyList());
        } finally {
            helper.removeWorker(WORKER_ID_CLIENTSIDE);
        }
    }

    /**
     * Create a ZIP file with entries which are unaligned.
     * @return the ZIP data
     * @throws Exception
     */
    private byte[] createUnalignedZip() throws Exception {
        // Create a ZIP file
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        ZipOutputStream out = new ZipOutputStream(bout);

        // name: 9, data: 1
        {
            ZipEntry entry1 = new ZipEntry("file1.txt");
            byte[] entry1Bytes = Hex.decode("ff");
            entry1.setMethod(ZipEntry.STORED);
            entry1.setCompressedSize(entry1Bytes.length);
            entry1.setSize(entry1Bytes.length);
            CRC32 crc = new CRC32();
            crc.update(entry1Bytes);
            entry1.setCrc(crc.getValue());
            out.putNextEntry(entry1);
            out.write(entry1Bytes);
            out.closeEntry();
        }

        // name: 10, data: 2
        {
            ZipEntry entry2 = new ZipEntry("file22.txt");
            byte[] entry2Bytes = Hex.decode("f1f2");
            entry2.setMethod(ZipEntry.STORED);
            entry2.setCompressedSize(entry2Bytes.length);
            entry2.setSize(entry2Bytes.length);
            CRC32 crc = new CRC32();
            crc.update(entry2Bytes);
            entry2.setCrc(crc.getValue());
            out.putNextEntry(entry2);
            out.write(entry2Bytes);
            out.closeEntry();
        }

        // name: 11, data: 3
        {
            ZipEntry entry3 = new ZipEntry("file333.txt");
            byte[] entry3Bytes = Hex.decode("f1f2f3");
            entry3.setMethod(ZipEntry.STORED);
            entry3.setCompressedSize(entry3Bytes.length);
            entry3.setSize(entry3Bytes.length);
            CRC32 crc = new CRC32();
            crc.update(entry3Bytes);
            entry3.setCrc(crc.getValue());
            out.putNextEntry(entry3);
            out.write(entry3Bytes);
            out.closeEntry();
        }

        // name: 12, data: 4
        {
            ZipEntry entry4 = new ZipEntry("file4444.txt");
            byte[] entry4Bytes = Hex.decode("f1f2f3f4");
            entry4.setMethod(ZipEntry.STORED);
            entry4.setCompressedSize(entry4Bytes.length);
            entry4.setSize(entry4Bytes.length);
            CRC32 crc = new CRC32();
            crc.update(entry4Bytes);
            entry4.setCrc(crc.getValue());
            out.putNextEntry(entry4);
            out.write(entry4Bytes);
            out.closeEntry();
        }

        out.finish();
        return bout.toByteArray();
    }

    /**
     * Test signing of a JAR/ZIP file and check that it is 'zipaligned'.
     * @throws Exception
     */
    @Test
    public void testSignZIPAligned() throws Exception {
        LOG.info("testSignZIPAligned");

        // Get some ZIP data with entries which are unaligned
        final byte[] zipFile = createUnalignedZip();
        
        try {
            addSigner();
            workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
            byte[] data = signAndAssertOk(zipFile, WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-256",
                "-extraoption", "ZIPALIGN=TRUE" }, 
                    JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
            assertAllZipAligned(true, data);
        } finally {
            helper.removeWorker(WORKER_ID_CLIENTSIDE);
        }
    }

    /**
     * Test signing of a JAR/ZIP file and check that it is not 'zipaligned'
     * by default.
     * @throws Exception
     */
    @Test
    public void testSignZIPAligned_default() throws Exception {
        LOG.info("testSignZIPAligned_default");

        // Get some ZIP data with entries which are unaligned
        final byte[] zipFile = createUnalignedZip();

        try {
            addSigner();
            workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
            byte[] data = signAndAssertOk(zipFile, WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-256" }, 
                    JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
            assertAllZipAligned(false, data);
        } finally {
            helper.removeWorker(WORKER_ID_CLIENTSIDE);
        }
    }

    /**
     * Test signing of a JAR/ZIP file and specify zipAlign=false and check that
     * it is not 'zipaligned'.
     * @throws Exception
     */
    @Test
    public void testSignZIPAligned_false() throws Exception {
        LOG.info("testSignZIPAligned_false");

        // Get some ZIP data with entries which are unaligned
        final byte[] zipFile = createUnalignedZip();

        try {
            addSigner();
            workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
            byte[] data = signAndAssertOk(zipFile, WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-256",
                "-extraoption", "ZIPALIGN=FALSE" }, 
                    JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
            assertAllZipAligned(false, data);
        } finally {
            helper.removeWorker(WORKER_ID_CLIENTSIDE);
        }
    }

    private void assertAllZipAligned(final boolean expectAllAligned, byte[] data) throws Exception {
        // Parse the resulting JAR file
        File signedFile = File.createTempFile("test-zip", ".signed");
        FileUtils.writeByteArrayToFile(signedFile, data);
        JarFile jar = new JarFile(signedFile, true);

        // Loop over each entry and keep track of the offset at which the data
        // begins
        Enumeration<JarEntry> entries = jar.entries();
        int offset = 0;
        final StringBuilder sb = new StringBuilder();
        boolean allStoredAligned = true;
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();

            // Get the lengths of the variable length header fields
            final int nameLen = entry.getName().getBytes(StandardCharsets.UTF_8).length;
            final int extraLen = entry.getExtra() == null ? 0 : entry.getExtra().length;

            // The length of the header
            final long totalHeader = JarFile.LOCHDR + nameLen + extraLen;

            // The length of the data (after the header / before the next entry)
            final long dataLen = entry.getCompressedSize();

            // Is the data starting at an offset which is a multiple of 4?
            final boolean multiple = (offset + totalHeader) % 4 == 0;

            // Output the entry for troubleshooting
            final String entryInfo = "Entry at " + offset +  ": Header(" + JarFile.LOCHDR + ",\"" + entry.getName() + "\" (" + nameLen + ")," + extraLen + "=" + totalHeader + ") Data at " + (offset + totalHeader) + " (" + (multiple ? "aligned" : "unaligned")  + ") : " + dataLen + " " + (entry.getMethod() != JarEntry.STORED ? "skipped" : "");
            LOG.info(entryInfo);
            sb.append(entryInfo);

            // Register if any stored entry was not aligned
            if (entry.getMethod() == JarEntry.STORED && !multiple) {
                allStoredAligned = false;
            }

            // Increase the offset with this entry
            offset += totalHeader + dataLen;
        }

        if (expectAllAligned) {
            assertTrue("All STORED entries should be on multiple:\n" + sb.toString(),
                    allStoredAligned);
        } else {
            assertFalse("Some STORED entries should be unaligned:\n" + sb.toString(),
                    allStoredAligned);
        }
    }

    /**
     * Test signing an already signed file again with the same digest algorithm
     * and an other signer name.
     * Note: The file is assumed to have an existing signature with an other
     * name than CERT.SF/RSA and to have SHA-256-Digest entries in MANIFEST.MF.
     * @throws Exception
     */
    @Test
    public void testSignAgain_CERT0_SHA256() throws Exception {
        LOG.info("testSignAgain_CERT0_SHA256");

        try (CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFileWithSignature)) {

            // Extract the certificate(s) from previous signature(s)
            // And extract all signature entries
            Collection<WrappedJarEntry> sigEntries = new LinkedList<>();
            Collection<Certificate> signerCerts = new LinkedList<>();
            gatherPreviousSignatures(requestData, sigEntries, signerCerts);
            if (sigEntries.size() < 1) {
                throw new Exception("Test expects " + executableFileWithSignature + " to have at least one existing signature");
            }
            boolean found = false;
            for (WrappedJarEntry entry : sigEntries) {
                if (entry.getName().equalsIgnoreCase("META-INF/CERT0.SF")) {
                    found = true;
                }
            }
            if (!found) {
                throw new Exception("Test expects " + executableFileWithSignatureTS + " to have CERT0.SF");
            }

            // Note: keepSignatures
            try {
                addSigner();
                workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
                signAndAssertOk(requestData.getAsByteArray(), WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-256", 
                    "-extraoption", "SIGNATURE_NAME_VALUE=CERT2",
                    "-extraoption", "KEEPSIGNATURES=TRUE"}, 
                        JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, signerCerts, sigEntries);
                
            } finally {
                helper.removeWorker(WORKER_ID_CLIENTSIDE);
            }
        }
    }

    /**
     * Test signing an already signed file again replacing the existing
     * signatures.
     * Note: The file is assumed to have an existing signature.
     * @throws Exception
     */
    @Test
    public void testSignAgain_replaceSigs() throws Exception {
        LOG.info("testSignAgain_replaceSigs");
        try (CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFileWithSignature)) {
            // Extract the certificate(s) from previous signature(s)
            // And extract all signature entries
            Collection<WrappedJarEntry> sigEntries = new LinkedList<>();
            Collection<Certificate> signerCerts = new LinkedList<>();
            gatherPreviousSignatures(requestData, sigEntries, signerCerts);
            if (sigEntries.size() < 1) {
                throw new Exception("Test expects " + executableFileWithSignature + " to have at least one existing signature");
            }

            // Expect old sigs to get removed
            sigEntries = Collections.<WrappedJarEntry>emptyList();
            signerCerts = Collections.<Certificate>emptyList();

            // Note: keepSignatures=false
            try {
                addSigner();
                workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
                signAndAssertOk(FileUtils.readFileToByteArray(executableFileWithSignature), WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA1", 
                    "-extraoption", "KEEPSIGNATURES=FALSE"}, 
                        JAVA_SHA1, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, signerCerts, sigEntries);
                
            } finally {
                helper.removeWorker(WORKER_ID_CLIENTSIDE);
            }
        }
    }

    /**
     * Test signing of a normal ZIP file (one without META-INF/MANIFEST.MF),
     * using the KEEPSIGNATURES=true option.
     * Purpose with test is to see that KEEPSIGNATURES does not freak out on
     * missing MANIFEST.MF.
     * @throws Exception
     */
    @Test
    public void testSignAgainZIP_withoutManifest() throws Exception {
        LOG.info("testSignAgainZIP_withoutManifest");

        // Create a ZIP file
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        ZipOutputStream out = new ZipOutputStream(bout);
        ZipEntry entry = new ZipEntry("file1.txt");
        out.putNextEntry(entry);
        out.write("Content of file 1.".getBytes("ASCII"));
        out.closeEntry();
        out.finish();

        final byte[] data = bout.toByteArray();
        
        try {
            addSigner();
            workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
            signAndAssertOk(data, WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-256", 
                "-extraoption", "KEEPSIGNATURES=TRUE"}, 
                    JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);

        } finally {
            helper.removeWorker(WORKER_ID_CLIENTSIDE);
        }
    }

    /**
     * Test signing an already signed file again with the same digest algorithm
     * and the same signer name.
     * Note: The file is assumed to have an existing signature with a
     * CERT.SF/RSA and to have SHA-256-Digest entries in MANIFEST.MF.
     * @throws Exception
     */
    @Test
    public void testSignAgain_sameAlias() throws Exception {
        LOG.info("testSignAgain_sameAlias");
        try (CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFileWithSignatureTS)) {

            // Extract the certificate(s) from previous signature(s)
            // And extract all signature entries
            Collection<WrappedJarEntry> sigEntries = new LinkedList<>();
            Collection<Certificate> signerCerts = new LinkedList<>();
            gatherPreviousSignatures(requestData, sigEntries, signerCerts);
            if (sigEntries.size() < 1) {
                throw new Exception("Test expects " + executableFileWithSignatureTS + " to have at least one existing signature");
            }
            boolean found = false;
            for (WrappedJarEntry entry : sigEntries) {
                if (entry.getName().equalsIgnoreCase("META-INF/CERT.SF")) {
                    found = true;
                }
            }
            if (!found) {
                throw new Exception("Test expects " + executableFileWithSignatureTS + " to have CERT.SF");
            }

            // Note: keepSignatures
            try {
                addSigner();
                workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
                signAndAssert(-2, requestData.getAsByteArray(), WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-256", 
                    "-extraoption", "SIGNATURE_NAME_VALUE=CERT",
                    "-extraoption", "REPLACESIGNATURE=FALSE",
                    "-extraoption", "KEEPSIGNATURES=TRUE"}, 
                        JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, signerCerts, sigEntries);
            } finally {
                helper.removeWorker(WORKER_ID_CLIENTSIDE);
            }
        }
    }

    /**
     * Test signing an already signed file again with the same digest algorithm
     * and the same signer name, replacing the signature file.
     * Note: The file is assumed to have an existing signature with a
     * CERT.SF/RSA and to have SHA-256-Digest entries in MANIFEST.MF.
     * @throws Exception
     */
    @Test
    public void testSignAgain_sameAlias_replace() throws Exception {
        LOG.info("testSignAgain_sameAlias_replace");
        try (CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFileWithSignatureTS)) {

            // Extract the certificate(s) from previous signature(s)
            // And extract all signature entries
            Collection<WrappedJarEntry> sigEntries = new LinkedList<>();
            Collection<Certificate> signerCerts = new LinkedList<>();
            gatherPreviousSignatures(requestData, sigEntries, signerCerts);
            if (sigEntries.size() < 1) {
                throw new Exception("Test expects " + executableFileWithSignatureTS + " to have at least one existing signature");
            }
            boolean found = false;
            for (WrappedJarEntry entry : sigEntries) {
                if (entry.getName().equalsIgnoreCase("META-INF/CERT.SF")) {
                    found = true;
                }
            }
            if (!found) {
                throw new Exception("Test expects " + executableFileWithSignatureTS + " to have CERT.SF");
            }

            // We expect the previous signature to be removed
            signerCerts.clear();
            sigEntries.clear();

            
            try {
                addSigner();
                workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
                
                // Note: replaceSignature=true,
                // keepSignatures=true (not important)
                signAndAssertOk(requestData.getAsByteArray(), WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-256", 
                    "-extraoption", "REPLACESIGNATURE=TRUE", 
                    "-extraoption", "SIGNATURE_NAME_VALUE=CERT",
                    "-extraoption", "KEEPSIGNATURES=TRUE"}, 
                        JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, signerCerts, sigEntries);

                // Note: replaceSignature=true,
                // keepSignatures=false (not important)
                signAndAssertOk(requestData.getAsByteArray(), WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-256", 
                    "-extraoption", "REPLACESIGNATURE=TRUE", 
                    "-extraoption", "SIGNATURE_NAME_VALUE=CERT",
                    "-extraoption", "KEEPSIGNATURES=FALSE"}, 
                        JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, signerCerts, sigEntries);
            } finally {
                helper.removeWorker(WORKER_ID_CLIENTSIDE);
            }
        }
    }

    /**
     * Tests that setting an incorrect value for KEEPSIGNATURES gives an error.
     * @throws Exception
     */
    @Test
    public void testOption_incorrectKeepSignatures() throws Exception {
        LOG.info("testOption_incorrectKeepSignatures");
        try {
            addSigner();
            workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
            signAndAssert(-2, FileUtils.readFileToByteArray(executableFile), WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-256", 
                "-extraoption", "KEEPSIGNATURES=_INCORRECT_VALUE_"}, 
                    JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, Collections.<Certificate>emptyList(), Collections.<WrappedJarEntry>emptyList());
        } finally {
            helper.removeWorker(WORKER_ID_CLIENTSIDE);
        }
    }

    /**
     * Tests that setting an incorrect value for REPLACESIGNATURE gives an error.
     * @throws Exception
     */
    @Test
    public void testOption_incorrectReplaceSignature() throws Exception {
        LOG.info("testOption_incorrectReplaceSignature");
        try {
            addSigner();
            workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
            signAndAssert(-2, FileUtils.readFileToByteArray(executableFile), WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-256", 
                "-extraoption", "REPLACESIGNATURE=_INCORRECT_VALUE_"}, 
                    JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, Collections.<Certificate>emptyList(), Collections.<WrappedJarEntry>emptyList());
        } finally {
            helper.removeWorker(WORKER_ID_CLIENTSIDE);
        }
    }

    /**
     * Test signing and specifying a signature name value.
     * @throws Exception
     */
    @Test
    public void testSigning_SignatureNameType_VALUE() throws Exception {
        LOG.info("testSigning_SignatureNameType_VALUE");
        try (CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile)) {
            addSigner();
            workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
            byte[] result = signAndAssertOk(requestData.getAsByteArray(), WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-256", 
                "-extraoption", "SIGNATURE_NAME_VALUE=ADAM"}, 
                    JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
            assertContainsSignatures(result, "ADAM", "RSA");
        } finally {
            helper.removeWorker(WORKER_ID_CLIENTSIDE);
        }
    }

    /**
     * Test signing without specifying signature name.
     * @throws Exception
     */
    @Test
    public void testSigning_SignatureName_default() throws Exception {
        LOG.info("testSigning_SignatureName_default");
        try (CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile)) {
            addSigner();
            workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
            byte[] result = signAndAssertOk(requestData.getAsByteArray(), WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-256" }, 
                    JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
            assertContainsSignatures(result, "SIGNSERV", "RSA");
        } finally {
            helper.removeWorker(WORKER_ID_CLIENTSIDE);
        }
    }

    /**
     * Tests that setting an incorrect value (too long) for
     * SIGNATURE_NAME_VALUE with type VALUE gives an error.
     * @throws Exception
     */
    @Test
    public void testOption_incorrectSignatureNameValue_tooLongVALUE() throws Exception {
        LOG.info("testOption_incorrectSignatureNameValue_tooLongVALUE");
        try {
            addSigner();
            workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
            signAndAssert(-2, FileUtils.readFileToByteArray(executableFile), WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-256", 
                "-extraoption", "SIGNATURE_NAME_VALUE=abcdefghi"}, // 9 ASCII characters is 1 too much
                    JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, Collections.<Certificate>emptyList(), Collections.<WrappedJarEntry>emptyList());
        } finally {
            helper.removeWorker(WORKER_ID_CLIENTSIDE);
        }
    }

    /**
     * Tests that setting an incorrect value (with spaces) for
     * SIGNATURE_NAME_VALUE with type VALUE gives an error.
     * @throws Exception
     */
    @Test
    public void testOption_incorrectSignatureNameValue_spacesInVALUE() throws Exception {
        LOG.info("testOption_incorrectSignatureNameValue_spacesInVALUE");
        try {
            addSigner();
            workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
            signAndAssert(-2, FileUtils.readFileToByteArray(executableFile), WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "SHA-256", 
                "-extraoption", "SIGNATURE_NAME_VALUE=a cdefgh"},
                    JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, Collections.<Certificate>emptyList(), Collections.<WrappedJarEntry>emptyList());
        } finally {
            helper.removeWorker(WORKER_ID_CLIENTSIDE);
        }
    }

    /**
      * Tests that the digest algorithm parameter can be formatted in a different way.
      * @throws Exception
     */
    @Test
    public void testDigestAlgorithmFormatting() throws Exception {
        LOG.info("testDigestAlgorithmFormatting");
        try {
            addSigner();
            workerSession.reloadConfiguration(WORKER_ID_CLIENTSIDE);
            signAndAssertOk(WORKER_ID_CLIENTSIDE, null, null, new String[] { "-digestalgorithm", "sha256" }, 
                    JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
        } finally {
            helper.removeWorker(WORKER_ID_CLIENTSIDE);
        }
    }

    private void gatherPreviousSignatures(ReadableData data, Collection<WrappedJarEntry> sigEntries, Collection<Certificate> signerCerts) throws Exception {
        JarFile jar = new JarFile(data.getAsFile(), true);
        Enumeration<JarEntry> entries = jar.entries();
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            IOUtils.copy(jar.getInputStream(entry), new NullOutputStream());

            // Gather the signer certificates from the first entry which has any
            if (signerCerts.isEmpty() && entry.getCodeSigners().length > 0) {
                signerCerts.addAll(getSignersCertificate(entry.getCodeSigners()));
            }

            // Gather signature entries
            if (entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".SF") || entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".DSA") || entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".EC") || entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".RSA")) {
                sigEntries.add(new WrappedJarEntry(entry));
            }
        }
    }

    private void assertContainsSignatures(byte[] data, String signatureName, String keyAlg) throws Exception {
        File origFile = null;
        try {
            origFile = File.createTempFile("orig-file", ".jar");

            FileUtils.writeByteArrayToFile(origFile, data);
            JarFile jar = new JarFile(origFile, true);
            Enumeration<JarEntry> entries = jar.entries();
            HashSet<String> names = new HashSet<>();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                names.add(entry.getName());
            }

            assertTrue("contains " + signatureName + ".SF: " + names, names.contains("META-INF/" + signatureName + ".SF"));
            assertTrue("contains " + signatureName + "." + keyAlg + ": " + names, names.contains("META-INF/" + signatureName + "." + keyAlg));
        } finally {
            if (origFile != null) {
                origFile.delete();
            }
        }
    }

    private static Collection<Certificate> getSignersCertificate(CodeSigner[] signers) {
        Collection<Certificate> result = new LinkedList<>();
        for (CodeSigner signer : signers) {
            result.add(signer.getSignerCertPath().getCertificates().iterator().next());
        }
        return result;
    }
    
    private void signAndAssertOk(int workerId, Integer tsId, Date timestamp, String[] extraArgs, String sfDigestAlg, ASN1ObjectIdentifier cmsDigestAlgOID, ASN1ObjectIdentifier sigAlgOID) throws Exception {
        signAndAssertOk(FileUtils.readFileToByteArray(executableFile), workerId, tsId, timestamp, extraArgs, sfDigestAlg, cmsDigestAlgOID, sigAlgOID, Collections.<Certificate>emptyList(), Collections.<WrappedJarEntry>emptyList());
    }
    
    public static byte[] signAndAssertOk(final byte[] sampleFile, int workerId, Integer tsId, Date timestamp, String[] extraArgs, String sfDigestAlg, ASN1ObjectIdentifier cmsDigestAlgOID, ASN1ObjectIdentifier sigAlgOID) throws Exception {
        return signAndAssertOk(sampleFile, workerId, tsId, timestamp, extraArgs, sfDigestAlg, cmsDigestAlgOID, sigAlgOID, Collections.<Certificate>emptyList(), Collections.<WrappedJarEntry>emptyList());
    }

    /**
     * Submits the given portable executable (as byte array) to the signer and
     * then checks that the signature seems to be made by the right signer etc.
     *
     * @param sampleFile binary to sign
     * @param workerId JArchiveSigner
     * @param tsId ID of TimeStampSigner
     * @param timestamp Faked time of signing to check with
     * @return the signed binary
     * @throws Exception 
     */
    public static byte[] signAndAssertOk(final byte[] sampleFile, int workerId, Integer tsId, Date timestamp, String[] extraArgs, String sfDigestAlg, ASN1ObjectIdentifier cmsDigestAlgOID, ASN1ObjectIdentifier sigAlgOID, Collection<Certificate> previousSignerCerts, Collection<WrappedJarEntry> previousSigEntries) throws Exception {
        return signAndAssert(CommandLineInterface.RETURN_SUCCESS, sampleFile, workerId, tsId, timestamp, extraArgs, sfDigestAlg, cmsDigestAlgOID, sigAlgOID, previousSignerCerts, previousSigEntries);
    }
    
    public static byte[] signAndAssert(final int expectedExitCode, final byte[] sampleFile, int workerId, Integer tsId, Date timestamp, String[] extraArgs, String sfDigestAlg, ASN1ObjectIdentifier cmsDigestAlgOID, ASN1ObjectIdentifier sigAlgOID, Collection<Certificate> previousSignerCerts, Collection<WrappedJarEntry> previousSigEntries) throws Exception {
        byte[] signedBinary = null;
        File signedFile = null;
        try {
            // call the CLI
            File inputFile = File.createTempFile("test-file", ".original");
            FileUtils.writeByteArrayToFile(inputFile, sampleFile);
            signedFile = File.createTempFile("test-file", ".signed");
            
            ArrayList<String> arguments = new ArrayList<>();
            arguments.add("signdocument");
            arguments.add("-clientside");
            arguments.add("-workerid");
            arguments.add(Integer.toString(workerId));
            arguments.add("-infile");
            arguments.add(inputFile.getAbsolutePath());
            arguments.add("-outfile");
            arguments.add(signedFile.getAbsolutePath());
            arguments.addAll(Arrays.asList(extraArgs));
            
            assertEquals("Status code", expectedExitCode,
                    cli.execute(arguments.toArray(new String[0])));
            
            if (expectedExitCode == CommandLineInterface.RETURN_SUCCESS) {
                signedBinary = FileUtils.readFileToByteArray(signedFile);

                try (JarFile jar = new JarFile(signedFile, true)) {

                    // Need each entry so that future calls to entry.getCodeSigners will return anything
                    Enumeration<JarEntry> entries = jar.entries();
                    while (entries.hasMoreElements()) {
                        JarEntry entry = entries.nextElement();
                        LOG.debug("Reading " + entry);
                        IOUtils.copy(jar.getInputStream(entry), new NullOutputStream());
                    }

                    Collection<WrappedJarEntry> sfEntries = new ArrayList<>();
                    Collection<WrappedJarEntry> cmsEntries = new ArrayList<>();

                    // Now check each entry
                    entries = jar.entries();
                    while (entries.hasMoreElements()) {
                        JarEntry entry = entries.nextElement();
                        if (entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".SF")) {
                            sfEntries.add(new WrappedJarEntry(entry));
                        } else if (entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".DSA")
                                || entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".EC")
                                || entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".RSA")) {
                            cmsEntries.add(new WrappedJarEntry(entry));
                        } else {
                            // Check that there is a code signer
                            LOG.debug("Veriyfing " + entry);
                            assertNotNull("code signers for entry: " + entry, entry.getCodeSigners());
                            assertEquals("Number of signatures in entry: " + entry, previousSignerCerts.size() + 1, entry.getCodeSigners().length);

                            final X509Certificate configuredSignerCert = (X509Certificate) getWorkerSessionS().getSignerCertificate(new WorkerIdentifier(workerId));

                            // Check that the signer's certificate is included
                            Collection<Certificate> certs = getSignersCertificate(entry.getCodeSigners());

                            assertTrue("should contain the configured certificate: " + configuredSignerCert.getSubjectX500Principal() + " in " + certs, certs.contains(configuredSignerCert));
                            assertTrue("should contain the previous signer certificate(s): " + previousSignerCerts + " in " + certs, certs.containsAll(previousSignerCerts));

                            // Check the right digest is used for the entry (Except for the manifest)
                            if (!"META-INF/MANIFEST.MF".equals(entry.getName().toUpperCase(Locale.ENGLISH))) {
                                assertTrue(sfDigestAlg + "-Digest missing for entry " + entry,
                                    entry.getAttributes().containsKey(new Attributes.Name(sfDigestAlg + "-Digest")));
                            }
                        }
                    }

                    // Get the signature file
                    byte[] sfData;
                    Collection<WrappedJarEntry> newSFEntries = new LinkedList<>(sfEntries);
                    newSFEntries.removeAll(previousSigEntries);
                    assertEquals("expected 1 new .SF in " + newSFEntries, 1, newSFEntries.size());
                    JarEntry sfEntry = newSFEntries.iterator().next();
                    sfData = IOUtils.toByteArray(jar.getInputStream(sfEntry));

                    // Parse the signature file and check the manifest digest
                    final Manifest sf = new Manifest(new ByteArrayInputStream(sfData));
                    final Attributes mainAttributes = sf.getMainAttributes();
                    assertTrue("x-Digest-Manifest in " + mainAttributes.keySet(),
                            mainAttributes.containsKey(new Attributes.Name(sfDigestAlg + "-Digest-Manifest")));

                    // Check the signature files
                    final byte[] cmsData;
                    Collection<JarEntry> newCMSEntries = new LinkedList<JarEntry>(cmsEntries);
                    newCMSEntries.removeAll(previousSigEntries);
                    assertEquals("expected 1 new .RSA/.DSA/.EC in " + newCMSEntries, 1, newCMSEntries.size());
                    cmsData = IOUtils.toByteArray(jar.getInputStream(newCMSEntries.iterator().next()));

                    //System.out.println(ASN1Dump.dumpAsString(new ASN1InputStream(cmsData).readObject()));

                    // SignedData with the content-to-be-signed filled in
                    final CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(sfData), cmsData);

                    // TODO: assertEquals("eContentType <TODO>", "1.3.6.1.4.1.311.2.1.4", signedData.getSignedContentTypeOID());

                    final SignerInformation si = (SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();

                    // Check certificate returned
                    final X509Certificate configuredSignerCert = (X509Certificate) getWorkerSessionS().getSignerCertificate(new WorkerIdentifier(workerId));

                    // Verify using the signer's certificate (the configured one)
                    assertTrue("Verification using signer certificate",
                            si.verify(new JcaSimpleSignerInfoVerifierBuilder().build(configuredSignerCert)));

                    // Check that the signer's certificate is included
                    Store certs = signedData.getCertificates();
                    Collection matches = certs.getMatches(new JcaX509CertificateHolderSelector(configuredSignerCert));
                    assertEquals("should match the configured certificate: " + matches, 1, matches.size());

                    // Testing that the SID works
                    Collection certCollection = certs.getMatches(si.getSID());
                    assertTrue("Matched signer cert", si.getSID().match(new X509CertificateHolder(configuredSignerCert.getEncoded())));
                    X509CertificateHolder certHolder = (X509CertificateHolder) certCollection.iterator().next();
                    assertArrayEquals("same cert returned", certHolder.getEncoded(), configuredSignerCert.getEncoded());

                    // Check the signature algorithm
                    assertEquals("Digest algorithm", cmsDigestAlgOID.toString(), si.getDigestAlgorithmID().getAlgorithm().toString());
                    assertEquals("Encryption algorithm", sigAlgOID.getId(), si.getEncryptionAlgOID());
                }
            }
            return signedBinary;
        } finally {
            if (signedFile != null) {
                signedFile.delete();
            }
        }
    }

    /** JarEntry wrapper implementing equals/hashCode using the name. */
    private static class WrappedJarEntry extends JarEntry {
        private final String name;

        public WrappedJarEntry(JarEntry je) {
            super(je);
            this.name = je.getName();
        }

        @Override
        public int hashCode() {
            int hash = 5;
            hash = 83 * hash + Objects.hashCode(this.name);
            return hash;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final WrappedJarEntry other = (WrappedJarEntry) obj;
            if (!Objects.equals(this.name, other.name)) {
                return false;
            }
            return true;
        }
    }

}
