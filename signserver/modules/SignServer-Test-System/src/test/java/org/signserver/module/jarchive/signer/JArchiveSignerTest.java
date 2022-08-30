/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.jarchive.signer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Timestamp;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import java.util.jar.JarOutputStream;
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
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampToken;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.FixMethodOrder;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.signserver.cli.CommandLineInterface;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.server.FixedTimeSource;
import org.signserver.testutils.ModulesTestCase;

/**
 * System tests for JArchiveSigner.
 *
 * This tests requires a running SignServer. For standalone unit tests
 * preferably use JArchiveSignerUnitTest instead.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@SuppressWarnings("PMD.UnusedFormalParameter") // JUnit requires parameter in constructor
public class JArchiveSignerTest {

    private static final Logger LOG = Logger.getLogger(JArchiveSignerTest.class);

    private static final int WORKER_ID = 8909;
    private static final String WORKER_NAME = "TestJArchiveSigner";
    private static final int TS_ID = 8908;
    private static final String TS_NAME = "TestTimeStampSigner";

    private static File executableFile;

    private static WorkerSessionRemote workerSession = getWorkerSessionS();
    private static ProcessSessionRemote processSession = getProcessSessionS();

    private final ModulesTestCase helper = new ModulesTestCase();

    @BeforeClass
    public static void beforeClass() throws Exception {
        executableFile = new File(PathUtil.getAppHome(), "lib/SignServer-ejb.jar");
        if (!executableFile.exists()) {
            throw new Exception("Missing sample binary: " + executableFile);
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

    protected String getWorkerName() {
        return WORKER_NAME;
    }
    
    protected void addSigner() throws Exception {
        helper.addJArchiveSigner(WORKER_ID, getWorkerName(), true);
    }

    protected int getWorkerId() {
        return WORKER_ID;
    }

    /**
     * Tests signing and verify the signature.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigning() throws Exception {
        LOG.info("testSigning");
        try {
            addSigner();
            workerSession.reloadConfiguration(getWorkerId());

            signAndAssertOk(getWorkerId(), null, null, null);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    private byte[] createJarWithCompressedDirectoryEntries() throws IOException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try (final JarOutputStream jos = new JarOutputStream(baos)) {
            // create root directory
            final ZipEntry orgEntry = new ZipEntry("org/");

            orgEntry.setMethod(ZipEntry.DEFLATED);
            jos.putNextEntry(orgEntry);

            // create file
            final ZipEntry fileEntry = new ZipEntry("org/SomeFile.txt");

            fileEntry.setMethod(ZipEntry.DEFLATED);
            jos.putNextEntry(fileEntry);
            jos.write("content".getBytes(StandardCharsets.UTF_8));

            final ZipEntry subdirectoryEntry = new ZipEntry("org/package");

            subdirectoryEntry.setMethod(ZipEntry.DEFLATED);
            jos.putNextEntry(subdirectoryEntry);

            final ZipEntry uncompressedFileEntry = new ZipEntry("org/packe/SomeOtherFile.txt");
            final byte[] content = "more content".getBytes(StandardCharsets.UTF_8);
            
            uncompressedFileEntry.setMethod(ZipEntry.STORED);
            uncompressedFileEntry.setSize(content.length);

            CRC32 crc = new CRC32();
            crc.update(content);
            uncompressedFileEntry.setCrc(crc.getValue());
            
            jos.putNextEntry(uncompressedFileEntry);
            jos.write(content);
        }

        return baos.toByteArray();
    }

    private byte[] createJarWithNonDeflatedManifest() throws Exception {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try (final ZipOutputStream zos = new ZipOutputStream(baos)) {
            // manually create manifest, set as STORED
            final byte[] manifestContent = "// empty manifest".getBytes(StandardCharsets.UTF_8);
            final Manifest man = new Manifest(new ByteArrayInputStream(manifestContent));

            // create entry for META-INF as first entry
            final ZipEntry metaInf = new ZipEntry("META-INF/");

            metaInf.setMethod(ZipEntry.DEFLATED);
            zos.putNextEntry(metaInf);

            // add the entry for MANIFEST.MF as second (using STORED method)
            final ZipEntry manifestEntry = new ZipEntry(JarFile.MANIFEST_NAME);

            manifestEntry.setMethod(ZipEntry.STORED);
            manifestEntry.setSize(manifestContent.length);

            CRC32 crc = new CRC32();
            crc.update(manifestContent);
            manifestEntry.setCrc(crc.getValue());
            man.write(zos);

            // create root directory
            final ZipEntry orgEntry = new ZipEntry("org/");

            orgEntry.setMethod(ZipEntry.DEFLATED);
            zos.putNextEntry(orgEntry);

            // create file
            final ZipEntry fileEntry = new ZipEntry("org/SomeFile.txt");

            fileEntry.setMethod(ZipEntry.DEFLATED);
            zos.putNextEntry(fileEntry);
            zos.write("content".getBytes(StandardCharsets.UTF_8));
        }

        return baos.toByteArray();
    }

    /**
     * Assert all entries from an original file is present, and has the
     * same compression method in the signed file.
     * 
     * @param origContents Contents of the original JAR file
     * @param signedContents Contents of the signed JAR file
     * @throws IOException 
     */
    private void assertExpectedEntries(final byte[] origContents,
                                       final byte[] signedContents)
            throws IOException {
        final ByteArrayInputStream origBis =
                new ByteArrayInputStream(origContents);
        final ByteArrayInputStream signedBis =
                new ByteArrayInputStream(signedContents);
        
        final Map<String, Integer> origEntries = new HashMap<>();

        // collect entries from the original JAR
        try (final JarInputStream jis = new JarInputStream(origBis)) {
            ZipEntry entry;

            while ((entry = jis.getNextJarEntry()) != null) {
                final String path = entry.getName();
                final int method = entry.getMethod();

                origEntries.put(path, method);
            }
        }

        final int numOrigEntries = origEntries.size();

        /*
         * JarInputStream will assume the first entry(s) is either the
         * MANIFEST.MF, or the META-INF directory entry followed by the
         * MANIFEST.MF, and those would not be enumerated when iterating
         * the entries
         */
        try (final JarInputStream jis = new JarInputStream(signedBis)) {
            ZipEntry entry;
            int accountedForEntries = 0;

            while ((entry = jis.getNextJarEntry()) != null) {
                final String path = entry.getName();
                final int method = entry.getMethod();

                if (origEntries.containsKey(path)) {
                    final int origMethod = origEntries.get(path);

                    assertEquals("Same compression method", origMethod, method);

                    accountedForEntries++;
                }
            }

            assertEquals("All entries from original JAR found", numOrigEntries,
                         accountedForEntries);
        }
    }

    /**
     * Test signing a JAR file with compressed directory entries.
     * Verifies the signature and also check that all entries appear in the
     * result with the same compression method.
     *
     * @throws Exception 
     */
    @Test
    public void testSigningDirectoryEntriesCompressed() throws Exception {
        LOG.info("testSigningDirectoryEntriesCompressed");
        try {
            final byte[] input = createJarWithCompressedDirectoryEntries();
            
            addSigner();
            
            final byte[] output = signAndAssertOk(input, getWorkerId(), null,
                                                  null, null);
            
            assertExpectedEntries(input, output);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test signing a JAR file a stored (not deflated) manifest.
     * Verifies the signature and also check that all entries appear in the
     * result with the same compression method.
     *
     * @throws Exception 
     */
    @Test
    public void testSigningStoredManifest() throws Exception {
        LOG.info("testSigningDirectoryEntriesCompressed");
        try {
            final byte[] input = createJarWithNonDeflatedManifest();
            
            addSigner();
            
            final byte[] output = signAndAssertOk(input, getWorkerId(), null,
                                                  null, null);
            
            assertExpectedEntries(input, output);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }
    
    
    /**
     * Tests signing using the SignServer TSA.
     * Using SHA-256 TSA digest algorithm.
     *
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigningWithInternalTSA_sha256() throws Exception {
        LOG.info("testSigningWithInternalTSA_sha256");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            helper.addTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner();
            workerSession.setWorkerProperty(getWorkerId(), "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(getWorkerId(), "DIGESTALGORITHM", "SHA-256"); // TODO: Test without!
            workerSession.setWorkerProperty(getWorkerId(), "TSA_DIGESTALGORITHM", "SHA-256");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "true");
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(getWorkerId());

            signAndAssertOk(getWorkerId(), TS_ID, time,
                            new AlgorithmIdentifier(TSPAlgorithms.SHA256));
        } finally {
            helper.removeWorker(getWorkerId());
            helper.removeWorker(TS_ID);
        }
    }

    /**
     * Tests signing using the SignServer TSA.
     * Using SHA-384 TSA digest algorithm.
     *
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigningWithInternalTSA_sha384() throws Exception {
        LOG.info("testSigningWithInternalTSA_sha384");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            helper.addTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner();
            workerSession.setWorkerProperty(getWorkerId(), "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(getWorkerId(), "DIGESTALGORITHM", "SHA-256"); // TODO: Test without!
            workerSession.setWorkerProperty(getWorkerId(), "TSA_DIGESTALGORITHM", "SHA-384");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "true");
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(getWorkerId());

            signAndAssertOk(getWorkerId(), TS_ID, time,
                            new AlgorithmIdentifier(TSPAlgorithms.SHA384));
        } finally {
            helper.removeWorker(getWorkerId());
            helper.removeWorker(TS_ID);
        }
    }

    /**
     * Tests signing using the SignServer TSA and requesting a policy OID.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigningWithInternalTSA_reqPolicy() throws Exception {
        LOG.info("testSigningWithInternalTSA_reqPolicy");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            helper.addTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner();
            workerSession.setWorkerProperty(getWorkerId(), "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(getWorkerId(), "TSA_POLICYOID", "1.2.7");
            workerSession.setWorkerProperty(getWorkerId(), "DIGESTALGORITHM", "SHA-256");
            workerSession.setWorkerProperty(getWorkerId(), "TSA_DIGESTALGORITHM", "SHA-256"); // As this is only supported by the MSAuthCodeSigner so far and jdk1.7.0_45 on Jenkins does not support SHA-256 time-stamps
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTEDPOLICIES", "1.2.3;1.2.7");
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(getWorkerId());

            // Check TSA policy OID
            byte[] data = signAndAssertOk(FileUtils.readFileToByteArray(executableFile),
                                          getWorkerId(), TS_ID, time,
                                          new AlgorithmIdentifier(TSPAlgorithms.SHA256));
            final CMSSignedData signedData = new CMSSignedData(getFirstSignatureData(data));
            final SignerInformation si = signedData.getSignerInfos().getSigners().iterator().next();
            TimeStampToken token = new TimeStampToken(new CMSSignedData(si.getUnsignedAttributes().get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14")).getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
            assertEquals("policy oid", new ASN1ObjectIdentifier("1.2.7"), token.getTimeStampInfo().getPolicy());
        } finally {
            helper.removeWorker(getWorkerId());
            helper.removeWorker(TS_ID);
        }
    }

    /**
     * Tests signing using the SignServer TSA and not requesting a policy OID.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigningWithInternalTSA_defaultPolicy() throws Exception {
        LOG.info("testSigningWithInternalTSA_defaultPolicy");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            helper.addTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner();
            // Note: No TSA_POLICYOID
            workerSession.setWorkerProperty(getWorkerId(), "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(getWorkerId(), "DIGESTALGORITHM", "SHA-256");
            workerSession.setWorkerProperty(getWorkerId(), "TSA_DIGESTALGORITHM", "SHA-256"); // As this is only supported by the MSAuthCodeSigner so far and jdk1.7.0_45 on Jenkins does not support SHA-256 time-stamps
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTEDPOLICIES", "1.2.3;1.2.7");
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(getWorkerId());

            // Check TSA policy OID
            byte[] data = signAndAssertOk(FileUtils.readFileToByteArray(executableFile),
                                          getWorkerId(), TS_ID, time,
                                          new AlgorithmIdentifier(TSPAlgorithms.SHA256));
            final CMSSignedData signedData = new CMSSignedData(getFirstSignatureData(data));
            final SignerInformation si = signedData.getSignerInfos().getSigners().iterator().next();
            TimeStampToken token = new TimeStampToken(new CMSSignedData(si.getUnsignedAttributes().get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14")).getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
            assertEquals("policy oid", new ASN1ObjectIdentifier("1.2.3"), token.getTimeStampInfo().getPolicy());
        } finally {
            helper.removeWorker(getWorkerId());
            helper.removeWorker(TS_ID);
        }
    }

    /**
     * Tests signing using an URL to the SignServer TSA.
     * This is just for testing, under high load
     * (>20 concurrent requests it may deadlock).
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigningWithExternalTSA() throws Exception {
        LOG.info("testSigningWithExternalTSA");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            helper.addTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner();
            workerSession.setWorkerProperty(getWorkerId(), "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_ID);
            workerSession.setWorkerProperty(getWorkerId(), "TSA_DIGESTALGORITHM", "SHA-256"); // As this is only supported by the MSAuthCodeSigner so far and jdk1.7.0_45 on Jenkins does not support SHA-256 time-stamps
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "true");
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(getWorkerId());

            signAndAssertOk(getWorkerId(), TS_ID, time,
                            new AlgorithmIdentifier(TSPAlgorithms.SHA256));
        } finally {
            helper.removeWorker(getWorkerId());
            helper.removeWorker(TS_ID);
        }
    }

    /**
     * Tests signing using an URL to the SignServer TSA.
     * Using SHA-256 digest for timestamps.
     * This is just for testing, under high load
     * (>20 concurrent requests it may deadlock).
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigningWithExternalTSA_sha256() throws Exception {
        LOG.info("testSigningWithExternalTSA_sha256");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            helper.addTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner();
            workerSession.setWorkerProperty(getWorkerId(), "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_ID);
            workerSession.setWorkerProperty(getWorkerId(), "TSA_DIGESTALGORITHM", "SHA-256");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "true");
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(getWorkerId());

            signAndAssertOk(getWorkerId(), TS_ID, time,
                            new AlgorithmIdentifier(TSPAlgorithms.SHA256));
        } finally {
            helper.removeWorker(getWorkerId());
            helper.removeWorker(TS_ID);
        }
    }

    /**
     * Tests signing using an URL to the SignServer TSA.
     * Using SHA-384 digest for timestamps.
     * This is just for testing, under high load
     * (>20 concurrent requests it may deadlock).
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigningWithExternalTSA_sha384() throws Exception {
        LOG.info("testSigningWithExternalTSA_sha384");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            helper.addTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner();
            workerSession.setWorkerProperty(getWorkerId(), "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_ID);
            workerSession.setWorkerProperty(getWorkerId(), "TSA_DIGESTALGORITHM", "SHA-384");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "true");
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(getWorkerId());

            signAndAssertOk(getWorkerId(), TS_ID, time,
                            new AlgorithmIdentifier(TSPAlgorithms.SHA384));
        } finally {
            helper.removeWorker(getWorkerId());
            helper.removeWorker(TS_ID);
        }
    }

    /**
     * Tests signing using an URL to the SignServer TSA and requesting a policy
     * OID.
     * This is just for testing, under high load
     * (>20 concurrent requests it may deadlock).
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigningWithExternalTSA_reqPolicy() throws Exception {
        LOG.info("testSigningWithExternalTSA_reqPolicy");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            helper.addTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner();
            workerSession.setWorkerProperty(getWorkerId(), "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_ID);
            workerSession.setWorkerProperty(getWorkerId(), "TSA_POLICYOID", "1.2.8");
            workerSession.setWorkerProperty(getWorkerId(), "TSA_DIGESTALGORITHM", "SHA-256"); // As this is only supported by the MSAuthCodeSigner so far and jdk1.7.0_45 on Jenkins does not support SHA-256 time-stamps
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTEDPOLICIES", "1.2.3;1.2.8");
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(getWorkerId());

            // Check TSA policy OID
            byte[] data = signAndAssertOk(FileUtils.readFileToByteArray(executableFile),
                                          getWorkerId(),
                                          TS_ID, time,
                                          new AlgorithmIdentifier(TSPAlgorithms.SHA256));
            final CMSSignedData signedData = new CMSSignedData(getFirstSignatureData(data));
            final SignerInformation si = signedData.getSignerInfos().getSigners().iterator().next();
            TimeStampToken token = new TimeStampToken(new CMSSignedData(si.getUnsignedAttributes().get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14")).getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
            assertEquals("policy oid", new ASN1ObjectIdentifier("1.2.8"), token.getTimeStampInfo().getPolicy());
        } finally {
            helper.removeWorker(getWorkerId());
            helper.removeWorker(TS_ID);
        }
    }

    /**
     * Tests username/password authentication for internal TSA.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigningWithInternalTSA_auth() throws Exception {
        LOG.info("testSigningWithInternalTSA_auth");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            helper.addTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner();
            workerSession.setWorkerProperty(getWorkerId(), "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(getWorkerId(), "TSA_USERNAME", username);
            workerSession.setWorkerProperty(getWorkerId(), "TSA_PASSWORD", password);
            workerSession.setWorkerProperty(getWorkerId(), "TSA_DIGESTALGORITHM", "SHA-256"); // As this is only supported by the MSAuthCodeSigner so far and jdk1.7.0_45 on Jenkins does not support SHA-256 time-stamps
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "true");
            workerSession.setWorkerProperty(TS_ID, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
            workerSession.setWorkerProperty(TS_ID, "USER.USER1", password);
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(getWorkerId());

            signAndAssertOk(getWorkerId(), TS_ID, time,
                            new AlgorithmIdentifier(TSPAlgorithms.SHA256));
        } finally {
            helper.removeWorker(getWorkerId());
            helper.removeWorker(TS_ID);
        }
    }

    /**
     * Tests username/password authentication for external TSA.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigningWithExternalTSA_auth() throws Exception {
        LOG.info("testSigningWithExternalTSA");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            helper.addTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner();
            workerSession.setWorkerProperty(getWorkerId(), "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_ID);
            workerSession.setWorkerProperty(getWorkerId(), "TSA_USERNAME", username);
            workerSession.setWorkerProperty(getWorkerId(), "TSA_PASSWORD", password);
            workerSession.setWorkerProperty(getWorkerId(), "TSA_DIGESTALGORITHM", "SHA-256"); // As this is only supported by the MSAuthCodeSigner so far and jdk1.7.0_45 on Jenkins does not support SHA-256 time-stamps
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "true");
            workerSession.setWorkerProperty(TS_ID, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
            workerSession.setWorkerProperty(TS_ID, "USER.USER1", password);
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(getWorkerId());

            signAndAssertOk(getWorkerId(), TS_ID, time,
                            new AlgorithmIdentifier(TSPAlgorithms.SHA256));
        } finally {
            helper.removeWorker(getWorkerId());
            helper.removeWorker(TS_ID);
        }
    }

    /**
     * Tests that incorrect TSA password gives error for external TSA.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigningWithExternalTSA_authWrong() throws Exception {
        LOG.info("testSigningWithExternalTSA");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            helper.addTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner();
            workerSession.setWorkerProperty(getWorkerId(), "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_ID);
            workerSession.setWorkerProperty(getWorkerId(), "TSA_USERNAME", username);
            workerSession.setWorkerProperty(getWorkerId(), "TSA_PASSWORD", "_WRONG-PASS_");
            workerSession.setWorkerProperty(getWorkerId(), "TSA_DIGESTALGORITHM", "SHA-256"); // As this is only supported by the MSAuthCodeSigner so far and jdk1.7.0_45 on Jenkins does not support SHA-256 time-stamps
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "true");
            workerSession.setWorkerProperty(TS_ID, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
            workerSession.setWorkerProperty(TS_ID, "USER.USER1", password);
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(getWorkerId());
            // CommandLineInterface.RETURN_ERROR expected due to 401 Unauthorized error in JArchiveSigner.ExternalTimeStampingSigner
            // resulting in SignServerException, however, asynchronous with delay
            signAndAssertError(getWorkerId(), TS_ID, time, new AlgorithmIdentifier(TSPAlgorithms.SHA256));
        } catch (SignServerException expected) { // NOPMD
            // OK
        } finally {
            helper.removeWorker(getWorkerId());
            helper.removeWorker(TS_ID);
        }
    }

    /**
     * Tests that incorrect TSA password gives error for internal TSA.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigningWithInternalTSA_authWrong() throws Exception {
        LOG.info("testSigningWithInternalTSA_auth");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            helper.addTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner();
            workerSession.setWorkerProperty(getWorkerId(), "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(getWorkerId(), "TSA_USERNAME", username);
            workerSession.setWorkerProperty(getWorkerId(), "TSA_PASSWORD", "_WRONG-PASS_");
            workerSession.setWorkerProperty(getWorkerId(), "TSA_DIGESTALGORITHM", "SHA-256"); // As this is only supported by the MSAuthCodeSigner so far and jdk1.7.0_45 on Jenkins does not support SHA-256 time-stamps
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "true");
            workerSession.setWorkerProperty(TS_ID, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
            workerSession.setWorkerProperty(TS_ID, "USER.USER1", password);
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(getWorkerId());
            // CommandLineInterface.RETURN_ERROR expected due to 401 Unauthorized error in JArchiveSigner.ExternalTimeStampingSigner
            // resulting in SignServerException, however, asynchronous with delay
            signAndAssertError(getWorkerId(), TS_ID, time,
                            new AlgorithmIdentifier(TSPAlgorithms.SHA256));
        } catch (SignServerException expected) { // NOPMD
            // OK
        } finally {
            helper.removeWorker(getWorkerId());
            helper.removeWorker(TS_ID);
        }
    }

    private void signAndAssertOk(int workerId, Integer tsId, Date timestamp,
                                 AlgorithmIdentifier expectedTSADigestAlgorithm) throws Exception {
        signAndAssertOk(FileUtils.readFileToByteArray(executableFile), workerId,
                                                      tsId, timestamp,
                                                      expectedTSADigestAlgorithm);
    }

    /**
     * Submits the given portable executable (as byte array) to the signer and
     * then checks that the signature seems to be made by the right signer etc.
     *
     * @param sampleFile binary to sign
     * @param workerId JArchiveSigner
     * @param tsId ID of TimeStampSigner
     * @param timestamp Faked time of signing to check with
     * @param expectedTSADigestAlgorithm The expected timestamp digest algorithm (when using a TSA)
     * @return the signed binary
     * @throws Exception in case of failure.
     */
    public static byte[] signAndAssertOk(final byte[] sampleFile,
                                         final int workerId,
                                         final Integer tsId,
                                         final Date timestamp,
                                         final AlgorithmIdentifier expectedTSADigestAlgorithm)
            throws Exception {
        return staticSignAndAssert(CommandLineInterface.RETURN_SUCCESS,
                sampleFile, workerId, tsId, timestamp, expectedTSADigestAlgorithm);
    }

    /**
     * Submits the given portable executable (as byte array) to the signer and
     * expects failure.
     *
     * @param workerId JArchiveSigner
     * @param tsId ID of TimeStampSigner
     * @param timestamp Faked time of signing to check with
     * @param expectedTSADigestAlgorithm The expected timestamp digest algorithm (when using a TSA)
     * @throws Exception in case of failure.
     */
    public static void signAndAssertError(
                                         final int workerId,
                                         final Integer tsId,
                                         final Date timestamp,
                                         final AlgorithmIdentifier expectedTSADigestAlgorithm)
            throws Exception {
        staticSignAndAssert(CommandLineInterface.RETURN_ERROR,
                FileUtils.readFileToByteArray(executableFile), workerId, tsId, timestamp, expectedTSADigestAlgorithm);
    }

    /**
     * Submits the given portable executable (as byte array) to the signer and
     * then checks that the signature seems to be made by the right signer etc.
     *
     * @param expectedCliReturnCode expected CLI execution return code.
     * @param sampleFile binary to sign
     * @param workerId JArchiveSigner
     * @param tsId ID of TimeStampSigner
     * @param timestamp Faked time of signing to check with
     * @param expectedTSADigestAlgorithm The expected timestamp digest algorithm (when using a TSA)
     * @return the signed binary
     * @see CommandLineInterface#RETURN_SUCCESS
     * @see CommandLineInterface#RETURN_INVALID_ARGUMENTS
     * @see CommandLineInterface#RETURN_ERROR
     * @throws Exception in case of failure.
     */
    public byte[] signAndAssert(final int expectedCliReturnCode,
                                         final byte[] sampleFile,
                                         final int workerId,
                                         final Integer tsId,
                                         final Date timestamp,
                                         final AlgorithmIdentifier expectedTSADigestAlgorithm)
            throws Exception {
        return staticSignAndAssert(expectedCliReturnCode, sampleFile, workerId,
                                   tsId, timestamp, expectedTSADigestAlgorithm);
    }

    public static byte[] staticSignAndAssert(final int expectedCliReturnCode,
                                         final byte[] sampleFile,
                                         final int workerId,
                                         final Integer tsId,
                                         final Date timestamp,
                                         final AlgorithmIdentifier expectedTSADigestAlgorithm)
            throws Exception {
        byte[] signedBinary;
        File signedFile = null;
        try {
                GenericSignRequest request = new GenericSignRequest(200, sampleFile);
                GenericSignResponse response = (GenericSignResponse) processSession.process(new WorkerIdentifier(workerId), request, new RemoteRequestContext());

                signedBinary = response.getProcessedData();
                signedFile = File.createTempFile("test-file", ".signed");
                FileUtils.writeByteArrayToFile(signedFile, signedBinary);

            assertJarSignatureOk(signedFile, tsId, timestamp, expectedTSADigestAlgorithm);
            return signedBinary;
        } finally {
            if (signedFile != null) {
                signedFile.delete();
            }
        }
    }

    /**
     * Verify the JAR signature.
     * @param signedFile JAR file to verify
     * @throws Exception in case of failure.
     */
    public static void assertJarSignatureOk(final File signedFile) throws Exception {
        assertJarSignatureOk(signedFile, null, null, null);
    }

    /**
     * Verify the JAR signature and timestamp if requested.
     *
     * @param signedFile JAR file to verify
     * @param tsId Worker Id of time-stamp signer
     * @param timestamp date
     * @param expectedTSADigestAlgorithm expected time-stamp digest algorithm
     * @throws Exception in case of failure.
     */
    public static void assertJarSignatureOk(final File signedFile, final Integer tsId, final Date timestamp, final AlgorithmIdentifier expectedTSADigestAlgorithm) throws Exception {
        try (JarFile jar = new JarFile(signedFile, true)) {

            // Need each entry so that future calls to entry.getCodeSigners will return anything
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                LOG.debug("Reading " + entry);
                IOUtils.copy(jar.getInputStream(entry), NullOutputStream.NULL_OUTPUT_STREAM);
            }

            // Now check each entry
            entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (!entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".SF")
                        && !entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".DSA")
                        && !entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".EC")
                        && !entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".RSA")
                        && !entry.getName().endsWith("/")) {

                    // Check that there is a code signer
                    LOG.debug("Veriyfing " + entry);
                    assertNotNull("code signers for entry: " + entry, entry.getCodeSigners());
                    assertEquals("Number of signatures in entry: " + entry, 1, entry.getCodeSigners().length);

                    if (tsId != null) {
                        // Check that the time is as given by ZeroTimeSource
                        Timestamp timestampToken = entry.getCodeSigners()[0].getTimestamp();
                        assertNotNull("timestamp in entry: " + entry, timestampToken);
                        Date signingTime = timestampToken.getTimestamp();
                        assertEquals("signingTime for entry: " + entry, timestamp, signingTime);

                        // The right TSA
                        Certificate tsaCert = timestampToken.getSignerCertPath().getCertificates().get(0);
                        assertEquals("TSA certificate", workerSession.getSignerCertificate(new WorkerIdentifier(tsId)), tsaCert);
                    }
                } else if (!entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".SF")
                        && !entry.getName().endsWith("/")) {
                    LOG.info("Reading: " + entry.getName());
                    final InputStream is = jar.getInputStream(entry);
                    final byte[] cmsData = IOUtils.toByteArray(is);
                    final CMSSignedData cms = new CMSSignedData(cmsData);
                    final SignerInformation si =
                            cms.getSignerInfos().getSigners().iterator().next();

                    final AttributeTable unsignedAttributes = si.getUnsignedAttributes();
                    final Attribute attr = unsignedAttributes != null ?
                            unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) :
                            null;

                    if (tsId != null) {
                        assertNotNull("Should contain the timestamping unsigned attribute",
                                attr);

                        // check timestamp token
                        final TimeStampToken tst =
                                new TimeStampToken(new CMSSignedData(attr.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
                        final AlgorithmIdentifier hashAlgorithm = tst.getTimeStampInfo().getHashAlgorithm();

                        assertEquals("Expected timestamp digest algorithm",
                                expectedTSADigestAlgorithm.getAlgorithm(),
                                hashAlgorithm.getAlgorithm());
                    } else {
                        assertNull("No timestamping unsigned attribute should be included",
                                attr);
                    }

                } else {
                    LOG.info("Ignoring non-class entry: " + entry);
                }
            }
        }
    }

    private byte[] getFirstSignatureData(byte[] data) throws Exception {
        File origFile = null;
        try {
            origFile = File.createTempFile("orig-file", ".jar");

            FileUtils.writeByteArrayToFile(origFile, data);
            JarFile jar = new JarFile(origFile, true);
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.getName().startsWith("META-INF/") && entry.getName().endsWith(".RSA")) {
                    return IOUtils.toByteArray(jar.getInputStream(entry));
                }
            }
            return null;
        } finally {
            if (origFile != null) {
                origFile.delete();
            }
        }
    }
}
