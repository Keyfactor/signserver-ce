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
package org.signserver.module.msauthcode.signer;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import javax.naming.NamingException;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.fail;
import net.jsign.DigestAlgorithm;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.asn1.authenticode.SpcPeImageData;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import net.jsign.pe.PEFile;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.apache.poi.poifs.filesystem.DocumentInputStream;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.junit.Test;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.cli.CommandLineInterface;
import org.signserver.client.cli.ClientCLI;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.server.FixedTimeSource;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;

/**
 * System tests for MSAuthCodeSigner.
 *
 * This tests requires a running SignServer. For standalone unit tests
 * preferably use MSAuthCodeSignerUnitTest instead.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MSAuthCodeSignerTest extends ModulesTestCase {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(MSAuthCodeSignerTest.class);

    private static final int WORKER_ID = 8901;
    private static final String WORKER_NAME = "TestMSAuthCodeSigner";
    private static final int TS_ID = 8902;
    private static final String TS_NAME = "TestAuthenticodeTimeStampSigner";
    private static final int TS_RFC_ID = 8903;
    private static final String TS_RFC_NAME = "TestRFC3161TimeStampSigner";

    private final File executableFile;
    private final File msiFile;
    
    private static WorkerSessionRemote workerSession = getWorkerSessionS();
    private static ProcessSessionRemote processSession = getProcessSessionS();
    
    private static final CLITestHelper cli = new CLITestHelper(ClientCLI.class);
    
    public MSAuthCodeSignerTest() throws Exception {
        executableFile = new File(PathUtil.getAppHome(), "res/test/HelloPE.exe");
        if (!executableFile.exists()) {
            throw new Exception("Missing sample binary: " + executableFile);
        }
        msiFile = new File(PathUtil.getAppHome(), "res/test/sample.msi");
        if (!msiFile.exists()) {
            throw new Exception("Missing sample MSI package: " + msiFile);
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
     * Tests signing using the SignServer TSA.
     * @throws Exception 
     */
    @Test
    public void testSigningPEWithInternalTSA() throws Exception {
        testSigningWithInternalTSA(false);
    }
    
    @Test
    public void testSigningMSIWithInternalTSA() throws Exception {
        testSigningWithInternalTSA(true);
    }
    
    private void testSigningWithInternalTSA(final boolean msi) throws Exception {
        LOG.info("testSigningWithInternalTSA");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addMSTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner(MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            if (msi) {
                signAndAssertOkMSI(WORKER_ID, TS_ID, time, false);
            } else {
                signAndAssertOk(WORKER_ID, TS_ID, time, false);
            }
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }
    
    
    @Test
    public void testSigningPEWithInternalRFCTSA() throws Exception {
        testSigningWithInternalRFCTSA(false);
    }
    
    @Test
    public void testSigningMSIWithInternalRFCTSA() throws Exception {
        testSigningWithInternalRFCTSA(true);
    }

    private void testSigningWithInternalRFCTSA(final boolean msi) throws Exception {
        LOG.info("testSigningWithInternalRFCTSA");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_RFC_ID, TS_RFC_NAME, true);
            addSigner(MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_RFC_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(WORKER_ID, "TIMESTAMP_FORMAT", "RFC3161");
            workerSession.setWorkerProperty(TS_RFC_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_RFC_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(TS_RFC_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            if (msi) {
                signAndAssertOkMSI(WORKER_ID, TS_RFC_ID, time, true);
            } else {
                signAndAssertOk(WORKER_ID, TS_RFC_ID, time, true);
            }
        } finally {
            removeWorker(TS_RFC_ID);
            removeWorker(WORKER_ID);
        }
    }

    /**
     * Tests signing using a URL to the SignServer TSA.
     * This is just for testing, under high load
     * (>20 concurrent requests it may deadlock).
     * @throws Exception 
     */
    @Test
    public void testSigningPEWithExternalTSA() throws Exception {
        testSigningWithExternalTSA(false);
    }
    
    @Test
    public void testSigningMSIWithExternalTSA() throws Exception {
        testSigningWithExternalTSA(true);
    }
    
    private void testSigningWithExternalTSA(final boolean msi) throws Exception {
        LOG.info("testSigningWithExternalTSA");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addMSTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner(MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_ID);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            signAndAssertOk(WORKER_ID, TS_ID, time, false);
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }
    
    /**
     * Tests signing using a URL to the SignServer TSA using an RFC 3161 TSA.
     * This is just for testing, under high load
     * (>20 concurrent requests it may deadlock).
     * @throws Exception 
     */
    @Test
    public void testSigningPEWithExternalRFCTSA() throws Exception {
        testSigningWithExternalRFCTSA(false);
    }
    
    @Test
    public void testSigningMSIWithExternalRFCTSA() throws Exception {
        testSigningWithExternalRFCTSA(true);
    }
    
    private void testSigningWithExternalRFCTSA(final boolean msi) throws Exception {
        LOG.info("testSigningWithExternalTSA");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_RFC_ID, TS_RFC_NAME, true);
            addSigner(MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_RFC_ID);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(WORKER_ID, "TIMESTAMP_FORMAT", "RFC3161");
            workerSession.setWorkerProperty(TS_RFC_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_RFC_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(TS_RFC_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            if (msi) {
                signAndAssertOkMSI(WORKER_ID, TS_RFC_ID, time, true);
            } else {
                signAndAssertOk(WORKER_ID, TS_RFC_ID, time, true);
            }
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_RFC_ID);
        }
    }
    
    /**
     * Tests username/password authentication for internal TSA.
     * @throws Exception 
     */
    @Test
    public void testSigningPEWithInternalTSA_auth() throws Exception {
        testSigningWithInternalTSA_auth(false);
    }
    
    @Test
    public void testSigningMSIWithInternalTSA_auth() throws Exception {
        testSigningWithInternalTSA_auth(true);
    }
    
    private void testSigningWithInternalTSA_auth(final boolean msi) throws Exception {
        LOG.info("testSigningWithInternalTSA_auth");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addMSTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner(MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_USERNAME", username);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_PASSWORD", password);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
            workerSession.setWorkerProperty(TS_ID, "USER.USER1", password);
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            if (msi) {
                signAndAssertOkMSI(WORKER_ID, TS_ID, time, false);
            } else {
                signAndAssertOk(WORKER_ID, TS_ID, time, false);
            }
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }
    
    /**
     * Tests username/password authentication for internal RFC 3161 TSA.
     * @throws Exception 
     */
    @Test
    public void testSigningPEWithInternalRFCTSA_auth() throws Exception {
        testSigningWithInternalRFCTSA_auth(false);
    } 
    
    @Test
    public void testSigningMSIWithInternalRFCTSA_auth() throws Exception {
        testSigningWithInternalRFCTSA_auth(true);
    }
    
    private void testSigningWithInternalRFCTSA_auth(final boolean msi) throws Exception {
        LOG.info("testSigningWithInternalTSA_auth");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_RFC_ID, TS_RFC_NAME, true);
            addSigner(MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_RFC_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_USERNAME", username);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_PASSWORD", password);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(WORKER_ID, "TIMESTAMP_FORMAT", "RFC3161");
            workerSession.setWorkerProperty(TS_RFC_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_RFC_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_RFC_ID, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
            workerSession.setWorkerProperty(TS_RFC_ID, "USER.USER1", password);
            workerSession.reloadConfiguration(TS_RFC_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            if (msi) {
                signAndAssertOkMSI(WORKER_ID, TS_RFC_ID, time, true);
            } else {
                signAndAssertOk(WORKER_ID, TS_RFC_ID, time, true);
            }
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_RFC_ID);
        }
    }
    
    /**
     * Tests username/password authentication for external TSA.
     * @throws Exception 
     */
    @Test
    public void testSigningPEWithExternalTSA_auth() throws Exception {
        testSigningWithExternalTSA_auth(false);
    }
    
    @Test
    public void testSigningMSIWithExternalTSA_auth() throws Exception {
        testSigningWithExternalTSA_auth(true);
    }
    
    private void testSigningWithExternalTSA_auth(final boolean msi) throws Exception {
        LOG.info("testSigningWithExternalTSA");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addMSTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner(MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_ID);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_USERNAME", username);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_PASSWORD", password);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
            workerSession.setWorkerProperty(TS_ID, "USER.USER1", password);
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            if (msi) {
                signAndAssertOkMSI(WORKER_ID, TS_ID, time, false);
            } else {
                signAndAssertOk(WORKER_ID, TS_ID, time, false);
            }
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }

    /**
     * Tests username/password authentication for external RFC 3161 TSA.
     * @throws Exception 
     */
    @Test
    public void testSigningPEWithExternalRFCTSA_auth() throws Exception {
        testSigningWithExternalRFCTSA_auth(false);
    }
    
    @Test
    public void testSigningMSIWithExternalRFCTSA_auth() throws Exception {
        testSigningWithExternalRFCTSA_auth(true);
    }

    private void testSigningWithExternalRFCTSA_auth(final boolean msi) throws Exception {
        LOG.info("testSigningWithExternalTSA");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_RFC_ID, TS_RFC_NAME, true);
            addSigner(MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_RFC_ID);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_USERNAME", username);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_PASSWORD", password);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(WORKER_ID, "TIMESTAMP_FORMAT", "RFC3161");
            workerSession.setWorkerProperty(TS_RFC_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_RFC_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_RFC_ID, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
            workerSession.setWorkerProperty(TS_RFC_ID, "USER.USER1", password);
            workerSession.reloadConfiguration(TS_RFC_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            if (msi) {
                signAndAssertOkMSI(WORKER_ID, TS_RFC_ID, time, true);
            } else {
                signAndAssertOk(WORKER_ID, TS_RFC_ID, time, true);
            }
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_RFC_ID);
        }
    }
    
    /**
     * Tests that incorrect TSA password gives error for external TSA.
     * @throws Exception 
     */
    @Test
    public void testSigningPEWithExternalTSA_authWrong() throws Exception {
        testSigningWithExternalTSA_authWrong(false);
    }
    
    @Test
    public void testSigningMSIWithExternalTSA_authWrong() throws Exception {
        testSigningWithExternalTSA_authWrong(true);
    }
    
    private void testSigningWithExternalTSA_authWrong(final boolean msi) throws Exception {
        LOG.info("testSigningWithExternalTSA");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addMSTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner(MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_ID);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_USERNAME", username);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_PASSWORD", "_WRONG-PASS_");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
            workerSession.setWorkerProperty(TS_ID, "USER.USER1", password);
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            signAndAssertFailed(WORKER_ID, msi ? msiFile : executableFile);
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }

    /**
     * Tests that incorrect TSA password gives error for internal TSA.
     * @throws Exception 
     */
    @Test
    public void testSigningPEWithInternalTSA_authWrong() throws Exception {
        testSigningWithInternalTSA_authWrong(false);
    }
    
    @Test
    public void testSigningMSIWithInternalTSA_authWrong() throws Exception {
        testSigningWithInternalTSA_authWrong(true);
    }
    
    private void testSigningWithInternalTSA_authWrong(final boolean msi) throws Exception {
        LOG.info("testSigningWithInternalTSA_auth");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addMSTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner(MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_USERNAME", username);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_PASSWORD", "_WRONG-PASS_");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.setWorkerProperty(TS_ID, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
            workerSession.setWorkerProperty(TS_ID, "USER.USER1", password);
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            signAndAssertFailed(WORKER_ID, msi ? msiFile : executableFile);
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }
    
    private void signAndAssertOk(int workerId, int tsId, Date timestamp,
                                 boolean rfcTimestamp) throws Exception {
        File signedFile = null;
        
        try {
            signedFile = signAndAssertOk(executableFile, workerId,
                        tsId, timestamp, rfcTimestamp);
        } finally {
            if (signedFile != null) {
                signedFile.delete();
            }
        }
    }
    
    private void signAndAssertOkMSI(int workerId, int tsId, Date timestamp,
                                boolean rfcTimestamp) throws Exception {
        File signedFile = null;
        
        try {
            signedFile = signAndAssertOkMSI(msiFile, workerId, tsId, timestamp,
                                            rfcTimestamp);
        } finally {
            if (signedFile != null) {
                signedFile.delete();
            }
        }
    }
    
    /**
     * Tests an expected failed signing (used by TSA auth failed tests).
     *
     * @param workerId
     * @throws Exception 
     */
    private void signAndAssertFailed(final int workerId,
                                     final File file) throws Exception {
        try {
            RemoteRequestContext requestContext = new RemoteRequestContext();
            byte[] sampleFile = FileUtils.readFileToByteArray(file);
            GenericSignRequest request = new GenericSignRequest(100, sampleFile);
            processSession.process(new WorkerIdentifier(workerId), request, requestContext);
            fail("Should fail signing data");
        } catch (SignServerException ex) {
            // expected
        }
    }
    
    /**
     * Submits the given portable executable to the signer and
     * then checks that the signature seems to be made by the right signer etc.
     *
     * @param sampleFile binary to sign
     * @param workerId MSAuthCodeSigner
     * @param tsId ID ofMSAuthCodeTimeStampSigner
     * @param timestamp Faked time of signing to check with
     * @param rfcTimestamp True if the test should assume an RFC3161 timestamp
     * @return the signed binary
     * @throws Exception 
     */
    public static File signAndAssertOk(final File sampleFile, int workerId,
                                       final int tsId, Date timestamp,
                                       boolean rfcTimestamp) throws Exception {
        final File signedFile = File.createTempFile("test-file", ".signed");
        PEFile pe = null;
        
        try {
            // call the CLI
            assertEquals("Status code", CommandLineInterface.RETURN_SUCCESS,
                    cli.execute("signdocument", "-workerid", Integer.toString(workerId),
                                "-infile", sampleFile.getAbsolutePath(),
                                "-outfile", signedFile.getAbsolutePath()));
            pe = new PEFile(signedFile);

            List<CMSSignedData> signatures = pe.getSignatures();
            assertEquals("Number of signatures", 1, signatures.size());


            // Reconstruct the data "to be signed"

            DigestAlgorithm digestAlg = DigestAlgorithm.of("SHA1");
            byte[] sha1 = pe.computeDigest(digestAlg);
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(X509ObjectIdentifiers.id_SHA1, DERNull.INSTANCE);
            DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, sha1);
            SpcAttributeTypeAndOptionalValue sataov =
                new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_PE_IMAGE_DATA_OBJID,
                                                     new SpcPeImageData());
            SpcIndirectDataContent spcIndirectDataContent =
                    new SpcIndirectDataContent(sataov, digestInfo);
            final byte[] idcBytes = spcIndirectDataContent.toASN1Primitive().getEncoded("DER");
            final byte[] content = new byte[idcBytes.length - 2];
            System.arraycopy(idcBytes, 2, content, 0, idcBytes.length - 2);

            // SignedData with the content-to-be-signed filled in
            final CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(content), signatures.get(0).getEncoded());

            assertTimestampOk(signedData, timestamp, tsId, rfcTimestamp);
            
            return signedFile;
        } finally {
            if (pe != null) {
                pe.close();
            }
        }
    }
    
    /**
     * Submit given MSI file to the signer and assert that the signed file
     * has a DigitalSignature entry and contains a correct timestamp.
     * The checks for the actual signature is done in the unit tests for
     * various algorithms etc.
     * 
     * @param sampleFile
     * @param workerId
     * @param tsId
     * @param timestamp
     * @param rfcTimestamp
     * @return
     * @throws Exception 
     */
    public static File signAndAssertOkMSI(final File sampleFile, int workerId,
                                          final int tsId, Date timestamp,
                                          boolean rfcTimestamp) throws Exception {
        final File signedFile = File.createTempFile("test-file", ".signed");

        // call the CLI
        assertEquals("Status code", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("signdocument", "-workerid", Integer.toString(workerId),
                            "-infile", sampleFile.getAbsolutePath(),
                            "-outfile", signedFile.getAbsolutePath()));
        try (final POIFSFileSystem fs = new POIFSFileSystem(signedFile)) {
            assertTrue("Has signature", fs.getRoot().hasEntry("\05DigitalSignature"));
            try (final DocumentInputStream dis =
                fs.createDocumentInputStream("\05DigitalSignature")) {
                final byte[] buf = new byte[dis.available()];

                dis.read(buf);
             
                final CMSSignedData cms = new CMSSignedData(buf);
                
                assertTimestampOk(cms, timestamp, tsId, rfcTimestamp);
            }
        }
        
        return signedFile;
    }
    
    private static void assertTimestampOk(final CMSSignedData signedData,
                                   final Date timestamp,
                                   final int tsId,
                                   final boolean rfcTimestamp) throws Exception {
        final SignerInformation si = (SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();

        if (rfcTimestamp) {
            Attribute attr = si.getUnsignedAttributes().get(AuthenticodeObjectIdentifiers.SPC_RFC3161_OBJID);
            assertNotNull("SPC_RFC3161_OBJID", attr);

            ASN1Set set = attr.getAttrValues();
            ASN1Sequence seq = (ASN1Sequence) set.getObjectAt(0);

            CMSSignedData cms = new CMSSignedData(seq.toASN1Primitive().getEncoded());
            TimeStampToken token = new TimeStampToken(cms);
            TimeStampTokenInfo timeStampInfo = token.getTimeStampInfo();

            assertEquals("signingTime", timestamp, timeStampInfo.getGenTime());

            SignerId sid = token.getSID();
            X509CertificateHolder holder =
                    (X509CertificateHolder) cms.getCertificates().getMatches(sid).iterator().next();

            assertEquals("TSA subject DN",
                    ((X509Certificate) workerSession.getSignerCertificate(new WorkerIdentifier(tsId))).getSubjectX500Principal().getName(),
                    new JcaX509CertificateConverter().getCertificate(holder).getSubjectX500Principal().getName());
        } else {
            // Get the timestamp
            Attribute attr = si.getUnsignedAttributes().get(CMSAttributes.counterSignature);
            assertNotNull("counterSignature", attr);
            SignerInformationStore counterSignature = si.getCounterSignatures();

            Collection signers = counterSignature.getSigners();
            assertEquals(1, signers.size());
            SignerInformation si2 = (SignerInformation) signers.iterator().next();

            // Check that the time is as given by ZeroTimeSource
            Date signingTime = Time.getInstance(si2.getSignedAttributes().get(CMSAttributes.signingTime).getAttrValues().getObjectAt(0)).getDate();
            assertEquals("signingTime", timestamp, signingTime);

            // Check that the right TSA is used by checking that we can verify the signature with the expected signer cert
            // XXX: BouncyCastle reports "[For counter signatures,] the signedAttributes field MUST NOT contain a content-type attribute"
            // however the specification "Authenticode_PE.docx" seems to specify that there should be a content-type
            //assertTrue("counterSignature verifies", si2.verify(new JcaSimpleSignerInfoVerifierBuilder().build((X509Certificate) workerSession.getSignerCertificate(tsId))));
            // Instead just check that the a certificate with the expected subject DN is there

            X509CertificateHolder holder = (X509CertificateHolder) signedData.getCertificates().getMatches(si2.getSID()).iterator().next();

            assertEquals("TSA subject DN",
                    ((X509Certificate) workerSession.getSignerCertificate(new WorkerIdentifier(tsId))).getSubjectX500Principal().getName(),
                    new JcaX509CertificateConverter().getCertificate(holder).getSubjectX500Principal().getName());
        }
    }
}
