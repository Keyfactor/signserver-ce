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

import java.io.File;
import java.security.Timestamp;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import javax.naming.NamingException;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.fail;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.NullOutputStream;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Test;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
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
public class JArchiveSignerTest extends ModulesTestCase {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(JArchiveSignerTest.class);

    private static final int WORKER_ID = 8909;
    private static final String WORKER_NAME = "TestJArchiveSigner";
    private static final int TS_ID = 8908;
    private static final String TS_NAME = "TestTimeStampSigner";
    
    private final File executableFile;
    
    private static WorkerSessionRemote workerSession = getWorkerSessionS();
    private static ProcessSessionRemote processSession = getProcessSessionS();
    
    public JArchiveSignerTest() throws Exception {
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

    /**
     * Tests signing and verify the signature.
     * @throws Exception 
     */
    @Test
    public void testSigning() throws Exception {
        LOG.info("testSigning");
        try {
            addJArchiveSigner(WORKER_ID, WORKER_NAME, true);
            workerSession.reloadConfiguration(WORKER_ID);

            signAndAssertOk(WORKER_ID, null, null);
        } finally {
            removeWorker(WORKER_ID);
        }
    }
    
    /**
     * Tests signing using the SignServer TSA.
     * @throws Exception 
     */
    @Test
    public void testSigningWithInternalTSA() throws Exception {
        LOG.info("testSigningWithInternalTSA");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_ID, TS_NAME, true);
            addJArchiveSigner(WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "DIGESTALGORITHM", "SHA1"); // TODO: Test without!
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "true");
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            signAndAssertOk(WORKER_ID, TS_ID, time);
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }
    
    /**
     * Tests signing using the SignServer TSA and requesting a policy OID.
     * @throws Exception 
     */
    @Test
    public void testSigningWithInternalTSA_reqPolicy() throws Exception {
        LOG.info("testSigningWithInternalTSA_reqPolicy");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_ID, TS_NAME, true);
            addJArchiveSigner(WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_POLICYOID", "1.2.7");
            workerSession.setWorkerProperty(WORKER_ID, "DIGESTALGORITHM", "SHA1");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTEDPOLICIES", "1.2.3;1.2.7");
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            // Check TSA policy OID
            byte[] data = signAndAssertOk(FileUtils.readFileToByteArray(executableFile), WORKER_ID, TS_ID, time);
            final CMSSignedData signedData = new CMSSignedData(getFirstSignatureData(data));
            final SignerInformation si = (SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();
            TimeStampToken token = new TimeStampToken(new CMSSignedData(si.getUnsignedAttributes().get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14")).getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
            assertEquals("policy oid", new ASN1ObjectIdentifier("1.2.7"), token.getTimeStampInfo().getPolicy());
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }
    
    /**
     * Tests signing using the SignServer TSA and not requesting a policy OID.
     * @throws Exception 
     */
    @Test
    public void testSigningWithInternalTSA_defaultPolicy() throws Exception {
        LOG.info("testSigningWithInternalTSA_defaultPolicy");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_ID, TS_NAME, true);
            addJArchiveSigner(WORKER_ID, WORKER_NAME, true);
            // Note: No TSA_POLICYOID
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "DIGESTALGORITHM", "SHA1");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTEDPOLICIES", "1.2.3;1.2.7");
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            // Check TSA policy OID
            byte[] data = signAndAssertOk(FileUtils.readFileToByteArray(executableFile), WORKER_ID, TS_ID, time);
            final CMSSignedData signedData = new CMSSignedData(getFirstSignatureData(data));
            final SignerInformation si = (SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();
            TimeStampToken token = new TimeStampToken(new CMSSignedData(si.getUnsignedAttributes().get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14")).getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
            assertEquals("policy oid", new ASN1ObjectIdentifier("1.2.3"), token.getTimeStampInfo().getPolicy());
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }
    
    /**
     * Tests signing using an URL to the SignServer TSA.
     * This is just for testing, under high load
     * (>20 concurrent requests it may deadlock).
     * @throws Exception 
     */
    @Test
    public void testSigningWithExternalTSA() throws Exception {
        LOG.info("testSigningWithExternalTSA");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_ID, TS_NAME, true);
            addJArchiveSigner(WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_ID);
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "true");
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            signAndAssertOk(WORKER_ID, TS_ID, time);
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }
    
    /**
     * Tests signing using an URL to the SignServer TSA and requesting a policy
     * OID.
     * This is just for testing, under high load
     * (>20 concurrent requests it may deadlock).
     * @throws Exception 
     */
    @Test
    public void testSigningWithExternalTSA_reqPolicy() throws Exception {
        LOG.info("testSigningWithExternalTSA_reqPolicy");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_ID, TS_NAME, true);
            addJArchiveSigner(WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_ID);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_POLICYOID", "1.2.8");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTEDPOLICIES", "1.2.3;1.2.8");
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            // Check TSA policy OID
            byte[] data = signAndAssertOk(FileUtils.readFileToByteArray(executableFile), WORKER_ID, TS_ID, time);
            final CMSSignedData signedData = new CMSSignedData(getFirstSignatureData(data));
            final SignerInformation si = (SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();
            TimeStampToken token = new TimeStampToken(new CMSSignedData(si.getUnsignedAttributes().get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14")).getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
            assertEquals("policy oid", new ASN1ObjectIdentifier("1.2.8"), token.getTimeStampInfo().getPolicy());
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }
    
    /**
     * Tests username/password authentication for internal TSA.
     * @throws Exception 
     */
    @Test
    public void testSigningWithInternalTSA_auth() throws Exception {
        LOG.info("testSigningWithInternalTSA_auth");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_ID, TS_NAME, true);
            addJArchiveSigner(WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_USERNAME", username);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_PASSWORD", password);
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "true");
            workerSession.setWorkerProperty(TS_ID, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
            workerSession.setWorkerProperty(TS_ID, "USER.USER1", password);
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            signAndAssertOk(WORKER_ID, TS_ID, time);
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }
    
    /**
     * Tests username/password authentication for external TSA.
     * @throws Exception 
     */
    @Test
    public void testSigningWithExternalTSA_auth() throws Exception {
        LOG.info("testSigningWithExternalTSA");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_ID, TS_NAME, true);
            addJArchiveSigner(WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_ID);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_USERNAME", username);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_PASSWORD", password);
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "true");
            workerSession.setWorkerProperty(TS_ID, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
            workerSession.setWorkerProperty(TS_ID, "USER.USER1", password);
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            signAndAssertOk(WORKER_ID, TS_ID, time);
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }

    /**
     * Tests that incorrect TSA password gives error for external TSA.
     * @throws Exception 
     */
    public void testSigningWithExternalTSA_authWrong() throws Exception {
        LOG.info("testSigningWithExternalTSA");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_ID, TS_NAME, true);
            addJArchiveSigner(WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_ID);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_USERNAME", username);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_PASSWORD", "_WRONG-PASS_");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "true");
            workerSession.setWorkerProperty(TS_ID, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
            workerSession.setWorkerProperty(TS_ID, "USER.USER1", password);
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            signAndAssertOk(WORKER_ID, TS_ID, time);
            fail("Should have failed with SignServerException");
        } catch (SignServerException expected) { // NOPMD
            // OK
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }

    /**
     * Tests that incorrect TSA password gives error for internal TSA.
     * @throws Exception 
     */
    public void testSigningWithInternalTSA_authWrong() throws Exception {
        LOG.info("testSigningWithInternalTSA_auth");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_ID, TS_NAME, true);
            addJArchiveSigner(WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_USERNAME", username);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_PASSWORD", "_WRONG-PASS_");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTANYPOLICY", "true");
            workerSession.setWorkerProperty(TS_ID, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
            workerSession.setWorkerProperty(TS_ID, "USER.USER1", password);
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            signAndAssertOk(WORKER_ID, TS_ID, time);
            fail("Should have failed with SignServerException");
        } catch (SignServerException expected) { // NOPMD
            // OK
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }
    
    private void signAndAssertOk(int workerId, Integer tsId, Date timestamp) throws Exception {
        signAndAssertOk(FileUtils.readFileToByteArray(executableFile), workerId, tsId, timestamp);
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
    public static byte[] signAndAssertOk(final byte[] sampleFile, int workerId, Integer tsId, Date timestamp) throws Exception {
        File signedFile = null;
        JarFile jar = null;
        try {
            GenericSignRequest request = new GenericSignRequest(200, sampleFile);
            GenericSignResponse response = (GenericSignResponse) processSession.process(new WorkerIdentifier(workerId), request, new RemoteRequestContext());

            byte[] signedBinary = response.getProcessedData();

            signedFile = File.createTempFile("test-file", ".signed");
            FileUtils.writeByteArrayToFile(signedFile, signedBinary);
            jar = new JarFile(signedFile, true);

            // Need each entry so that future calls to entry.getCodeSigners will return anything
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                LOG.debug("Reading " + entry);
                IOUtils.copy(jar.getInputStream(entry), new NullOutputStream());
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
                } else {
                    LOG.info("Ignoring non-class entry: " + entry);
                }
            }

            return signedBinary;
        } finally {
            if (jar != null) {
                jar.close();
            }
            if (signedFile != null) {
                signedFile.delete();
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
