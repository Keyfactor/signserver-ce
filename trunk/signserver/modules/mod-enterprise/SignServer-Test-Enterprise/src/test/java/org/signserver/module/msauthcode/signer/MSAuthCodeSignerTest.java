/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.msauthcode.signer;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import javax.naming.NamingException;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
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
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.apache.poi.poifs.filesystem.DocumentInputStream;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
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
import org.signserver.module.msauthcode.common.SpcSipInfo;
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
    private static final String WORKER_NAME_CMS = "TestMSAuthCodeCMSSigner";
    private static final int TS_ID = 8902;
    private static final String TS_NAME = "TestAuthenticodeTimeStampSigner";
    private static final int TS_RFC_ID = 8903;
    private static final String TS_RFC_NAME = "TestRFC3161TimeStampSigner";

    private final File executableFile;
    private final File msiFile;
    private final File appxFile;
    
    private static WorkerSessionRemote workerSession = getWorkerSessionS();
    private static ProcessSessionRemote processSession = getProcessSessionS();
    
    private static final CLITestHelper cli = new CLITestHelper(ClientCLI.class);
    
    private static final byte[] P7X_SIGNATURE = new byte[] {(byte) 0x50, (byte) 0x4b, (byte) 0x43, (byte) 0x58};
    
    private enum FileType {
        PE,
        MSI,
        APPX
    }

    public MSAuthCodeSignerTest() throws Exception {
        executableFile = new File(PathUtil.getAppHome(), "res/test/HelloPE.exe");
        if (!executableFile.exists()) {
            throw new Exception("Missing sample binary: " + executableFile);
        }
        msiFile = new File(PathUtil.getAppHome(), "res/test/sample.msi");
        if (!msiFile.exists()) {
            throw new Exception("Missing sample MSI package: " + msiFile);
        }
        appxFile = new File(PathUtil.getAppHome(), "res/test/HelloAppx.appx");
        if (!appxFile.exists()) {
            throw new Exception("Missing sample APPX package: " + appxFile);
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
        testSigningWithInternalTSA(FileType.PE);
    }
    
    /**
     * Test signing when specifying timestamp format with a space, should expect
     * an Authenticode (legacy) TSA.
     *
     * @throws Exception 
     */
    @Test
    public void testSigningPEWithInternalTSAExtraSpaceInFormat() throws Exception {
        testSigningWithInternalTSA(FileType.PE, true);
    }
    
    @Test
    public void testSigningMSIWithInternalTSA() throws Exception {
        testSigningWithInternalTSA(FileType.MSI);
    }
    
    private void testSigningWithInternalTSA(final FileType fileType) throws Exception {
        LOG.info("testSigningWithInternalTSA");
        testSigningWithInternalTSA(fileType, false);
    }
    
    /**
     * Tests signing using the SignServer TSA.
     * @throws Exception 
     */
    @Test
    public void testSigningAPPXWithInternalTSA() throws Exception {
        testSigningWithInternalTSA(FileType.APPX);
    }
    
    /**
     * Test signing when specifying timestamp format with a space, should expect
     * an Authenticode (legacy) TSA.
     *
     * @throws Exception 
     */
    @Test
    public void testSigningAPPXWithInternalTSAExtraSpaceInFormat() throws Exception {
        testSigningWithInternalTSA(FileType.APPX, true);
    }

    private void testSigningWithInternalTSA(final FileType fileType,
                                            final boolean extraSpaceInFormat) throws Exception {
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addMSTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner(fileType == FileType.APPX ? AppxSigner.class.getName() : MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            // test that setting an empty TIMESTAMP_FORMAT actually assumes AUTHENTICODE, as per spec.
            workerSession.setWorkerProperty(WORKER_ID, "TIMESTAMP_FORMAT", extraSpaceInFormat ? " ": "");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            switch(fileType) {
                case MSI:
                    signAndAssertOkMSI(WORKER_ID, TS_ID, time, false, false);
                    break;
                case PE:
                    signAndAssertOk(WORKER_ID, TS_ID, time, false, false);
                    break;
                case APPX:
                    signAndAssertOkAPPX(WORKER_ID, TS_ID, time, false, false, workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)));
                    break;
            }
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }
    
    
    @Test
    public void testSigningPEWithInternalRFCTSA() throws Exception {
        testSigningWithInternalRFCTSA(FileType.PE);
    }
    
    @Test
    public void testSigningPEClientSideWithInternalRFCTSA() throws Exception {
        testSigningWithClientHashingInternalRFCTSA(FileType.PE);
    }
    
    @Test
    public void testSigningMSIWithInternalRFCTSA() throws Exception {
        testSigningWithInternalRFCTSA(FileType.MSI);
    }
    
    @Test
    public void testSigningMSIClientSideWithInternalRFCTSA() throws Exception {
        testSigningWithClientHashingInternalRFCTSA(FileType.MSI);
    }

    @Test
    public void testSigningAPPXWithInternalRFCTSA() throws Exception {
        testSigningWithInternalRFCTSA(FileType.APPX);
    }
    
    @Test
    public void testSigningAPPXClientSideWithInternalRFCTSA() throws Exception {
        testSigningWithClientHashingInternalRFCTSA(FileType.APPX);
    }
    
    
    private void testSigningWithInternalRFCTSA(final FileType fileType) throws Exception {
        LOG.info("testSigningWithInternalRFCTSA");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_RFC_ID, TS_RFC_NAME, true);
            addSigner(fileType == FileType.APPX ? AppxSigner.class.getName() : MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_RFC_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(WORKER_ID, "TIMESTAMP_FORMAT", "RFC3161");
            workerSession.setWorkerProperty(TS_RFC_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_RFC_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(TS_RFC_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            switch (fileType) {
                case MSI:
                    signAndAssertOkMSI(WORKER_ID, TS_RFC_ID, time, true, false);
                    break;
                case PE:
                    signAndAssertOk(WORKER_ID, TS_RFC_ID, time, true, false);
                    break;
                case APPX:
                    signAndAssertOkAPPX(WORKER_ID, TS_RFC_ID, time, true, false, workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)));
                    break;
            }
        } finally {
            removeWorker(TS_RFC_ID);
            removeWorker(WORKER_ID);
        }
    }
    
    private void testSigningWithClientHashingInternalRFCTSA(final FileType fileType) throws Exception {
        LOG.info("testSigningWithInternalRFCTSA");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_RFC_ID, TS_RFC_NAME, true);
            addSigner(fileType == FileType.APPX ? AppxCMSSigner.class.getName() : MSAuthCodeCMSSigner.class.getName(), WORKER_ID, WORKER_NAME_CMS, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_RFC_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(WORKER_ID, "ALLOW_CLIENTSIDEHASHING_OVERRIDE", "true");
            workerSession.setWorkerProperty(WORKER_ID, "ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256");
            workerSession.setWorkerProperty(TS_RFC_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_RFC_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(TS_RFC_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            switch (fileType) {
                case MSI:
                    signAndAssertOkMSI(WORKER_ID, TS_RFC_ID, time, true, true);
                    break;
                case PE:
                    signAndAssertOk(WORKER_ID, TS_RFC_ID, time, true, true);
                    break;
                case APPX:
                    signAndAssertOkAPPX(WORKER_ID, TS_RFC_ID, time, true, true, workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)));
                    break;
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
        testSigningWithExternalTSA(FileType.PE);
    }
    
    @Test
    public void testSigningMSIWithExternalTSA() throws Exception {
        testSigningWithExternalTSA(FileType.MSI);
    }
    
    @Test
    public void testSigningAPPXWithExternalTSA() throws Exception {
        testSigningWithExternalTSA(FileType.APPX);
    }
    
    private void testSigningWithExternalTSA(final FileType fileType) throws Exception {
        LOG.info("testSigningWithExternalTSA");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addMSTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner(fileType == FileType.APPX ? AppxSigner.class.getName() : MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_ID);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            switch (fileType) {
                case MSI:
                    signAndAssertOkMSI(WORKER_ID, TS_ID, time, false, false);
                    break;
                case PE:
                    signAndAssertOk(WORKER_ID, TS_ID, time, false, false);
                    break;
                case APPX:
                    signAndAssertOkAPPX(WORKER_ID, TS_ID, time, false, false, workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)));
                    break;
            }
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
        testSigningWithExternalRFCTSA(FileType.PE);
    }
    
    @Test
    public void testSigningPEClientSideWithExternalRFCTSA() throws Exception {
        testSigningWithClientHashingExternalRFCTSA(FileType.PE);
    }
    
    @Test
    public void testSigningMSIWithExternalRFCTSA() throws Exception {
        testSigningWithExternalRFCTSA(FileType.MSI);
    }
    
    @Test
    public void testSigningMSIClientSideWithExternalRFCTSA() throws Exception {
        testSigningWithClientHashingExternalRFCTSA(FileType.MSI);
    }
    
    @Test
    public void testSigningAPPXWithExternalRFCTSA() throws Exception {
        testSigningWithExternalRFCTSA(FileType.APPX);
    }
    
    @Test
    public void testSigningAPPXClientSideWithExternalRFCTSA() throws Exception {
        testSigningWithClientHashingExternalRFCTSA(FileType.APPX);
    }
    
    private void testSigningWithExternalRFCTSA(final FileType fileType) throws Exception {
        LOG.info("testSigningWithExternalTSA");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_RFC_ID, TS_RFC_NAME, true);
            addSigner(fileType == FileType.APPX ? AppxSigner.class.getName() : MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_RFC_ID);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(WORKER_ID, "TIMESTAMP_FORMAT", "RFC3161");
            workerSession.setWorkerProperty(TS_RFC_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_RFC_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(TS_RFC_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            switch (fileType) {
                case MSI:
                    signAndAssertOkMSI(WORKER_ID, TS_RFC_ID, time, true, false);
                    break;
                case PE: 
                    signAndAssertOk(WORKER_ID, TS_RFC_ID, time, true, false);
                    break;
                case APPX:
                    signAndAssertOkAPPX(WORKER_ID, TS_RFC_ID, time, true, false, workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)));
                    break;
            }
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_RFC_ID);
        }
    }
    
    private void testSigningWithClientHashingExternalRFCTSA(final FileType fileType) throws Exception {
        LOG.info("testSigningWithClientHashingExternalTSA");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_RFC_ID, TS_RFC_NAME, true);
            addSigner(fileType == FileType.APPX ? AppxCMSSigner.class.getName() : MSAuthCodeCMSSigner.class.getName(), WORKER_ID, WORKER_NAME_CMS, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerId=" + TS_RFC_ID);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(WORKER_ID, "ALLOW_CLIENTSIDEHASHING_OVERRIDE", "true");
            workerSession.setWorkerProperty(WORKER_ID, "ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256");
            workerSession.setWorkerProperty(TS_RFC_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_RFC_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(TS_RFC_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            switch (fileType) {
                case MSI:
                    signAndAssertOkMSI(WORKER_ID, TS_RFC_ID, time, true, true);
                    break;
                case PE:
                    signAndAssertOk(WORKER_ID, TS_RFC_ID, time, true, true);
                    break;
                case APPX:
                    signAndAssertOkAPPX(WORKER_ID, TS_RFC_ID, time, true, true, workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)));
                    break;
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
        testSigningWithInternalTSA_auth(FileType.PE);
    }
    
    @Test
    public void testSigningMSIWithInternalTSA_auth() throws Exception {
        testSigningWithInternalTSA_auth(FileType.MSI);
    }
    
    @Test
    public void testSigningAPPXWithInternalTSA_auth() throws Exception {
        testSigningWithInternalTSA_auth(FileType.APPX);
    }
    
    
    private void testSigningWithInternalTSA_auth(final FileType fileType) throws Exception {
        LOG.info("testSigningWithInternalTSA_auth");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addMSTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner(fileType == FileType.APPX ? AppxSigner.class.getName() : MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
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

            switch (fileType) {
                case MSI:
                    signAndAssertOkMSI(WORKER_ID, TS_ID, time, false, false);
                    break;
                case PE:
                    signAndAssertOk(WORKER_ID, TS_ID, time, false, false);
                    break;
                case APPX:
                    signAndAssertOkAPPX(WORKER_ID, TS_ID, time, false, false, workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)));
                    break;
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
        testSigningWithInternalRFCTSA_auth(FileType.PE);
    } 
    
    @Test
    public void testSigningMSIWithInternalRFCTSA_auth() throws Exception {
        testSigningWithInternalRFCTSA_auth(FileType.MSI);
    }
    
    private void testSigningWithInternalRFCTSA_auth(final FileType fileType) throws Exception {
        LOG.info("testSigningWithInternalTSA_auth");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_RFC_ID, TS_RFC_NAME, true);
            addSigner(fileType == FileType.APPX ? AppxSigner.class.getName() : MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
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

            switch (fileType) {
                case MSI:
                    signAndAssertOkMSI(WORKER_ID, TS_RFC_ID, time, true, false);
                    break;
                case PE:
                    signAndAssertOk(WORKER_ID, TS_RFC_ID, time, true, false);
                    break;
                case APPX:
                    signAndAssertOkAPPX(WORKER_ID, TS_RFC_ID, time, true, false, workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)));
                    break;
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
        testSigningWithExternalTSA_auth(FileType.PE);
    }
    
    @Test
    public void testSigningMSIWithExternalTSA_auth() throws Exception {
        testSigningWithExternalTSA_auth(FileType.MSI);
    }
    
    @Test
    public void testSigningAPPXWithExternalTSA_auth() throws Exception {
        testSigningWithExternalTSA_auth(FileType.APPX);
    }
    
    private void testSigningWithExternalTSA_auth(final FileType fileType) throws Exception {
        LOG.info("testSigningWithExternalTSA");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addMSTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner(fileType == FileType.APPX ? AppxSigner.class.getName() : MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
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

            switch (fileType) {
                case MSI:
                    signAndAssertOkMSI(WORKER_ID, TS_ID, time, false, false);
                    break;
                case PE:
                    signAndAssertOk(WORKER_ID, TS_ID, time, false, false);
                    break;
                case APPX:
                    signAndAssertOkAPPX(WORKER_ID, TS_ID, time, false, false, workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)));
                    break;
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
        testSigningWithExternalRFCTSA_auth(FileType.PE);
    }
    
    @Test
    public void testSigningMSIWithExternalRFCTSA_auth() throws Exception {
        testSigningWithExternalRFCTSA_auth(FileType.MSI);
    }
    
    @Test
    public void testSigningAPPXWithExternalRFCTSA_auth() throws Exception {
        testSigningWithExternalRFCTSA_auth(FileType.APPX);
    }

    private void testSigningWithExternalRFCTSA_auth(final FileType fileType) throws Exception {
        LOG.info("testSigningWithExternalTSA");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_RFC_ID, TS_RFC_NAME, true);
            addSigner(fileType == FileType.APPX ? AppxSigner.class.getName() : MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
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

            switch (fileType) {
                case MSI:
                    signAndAssertOkMSI(WORKER_ID, TS_RFC_ID, time, true, false);
                    break;
                case PE:
                    signAndAssertOk(WORKER_ID, TS_RFC_ID, time, true, false);
                    break;
                case APPX:
                    signAndAssertOkAPPX(WORKER_ID, TS_RFC_ID, time, true, false, workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)));
                    break;
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
        testSigningWithExternalTSA_authWrong(FileType.PE);
    }
    
    @Test
    public void testSigningMSIWithExternalTSA_authWrong() throws Exception {
        testSigningWithExternalTSA_authWrong(FileType.MSI);
    }
    
    @Test
    public void testSigningAPPXWithExternalTSA_authWrong() throws Exception {
        testSigningWithExternalTSA_authWrong(FileType.APPX);
    }
    
    private void testSigningWithExternalTSA_authWrong(final FileType fileType) throws Exception {
        LOG.info("testSigningWithExternalTSA");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addMSTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner(fileType == FileType.APPX ? AppxSigner.class.getName() : MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
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

            final File file;
            switch (fileType) {
                case PE:
                    file = executableFile;
                    break;
                case MSI:
                    file = msiFile;
                    break;
                case APPX:
                    file = appxFile;
                    break;
                default:
                    throw new Exception("Unsupported file type in test: " + fileType);
            }
            
            signAndAssertFailed(WORKER_ID, file);
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
        testSigningWithInternalTSA_authWrong(FileType.PE);
    }
    
    @Test
    public void testSigningMSIWithInternalTSA_authWrong() throws Exception {
        testSigningWithInternalTSA_authWrong(FileType.MSI);
    }
    
    @Test
    public void testSigningAPPXWithInternalTSA_authWrong() throws Exception {
        testSigningWithInternalTSA_authWrong(FileType.APPX);
    }
    
    private void testSigningWithInternalTSA_authWrong(final FileType fileType) throws Exception {
        LOG.info("testSigningWithInternalTSA_auth");
        try {
            String username = "user1";
            String password = "foo123åäö!!!###";
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addMSTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner(fileType == FileType.APPX ? AppxSigner.class.getName() : MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
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

            final File file;
            switch (fileType) {
                case PE:
                    file = executableFile;
                    break;
                case MSI:
                    file = msiFile;
                    break;
                case APPX:
                    file = appxFile;
                    break;
                default:
                    throw new Exception("Unsupported file type in test: " + fileType);
            }

            signAndAssertFailed(WORKER_ID, file);
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }
    
    private void signAndAssertOk(int workerId, int tsId, Date timestamp,
                                 boolean rfcTimestamp, boolean clientSide)
            throws Exception {
        File signedFile = null;
        
        try {
            signedFile = signAndAssertOk(executableFile, workerId,
                        tsId, timestamp, rfcTimestamp, clientSide);
        } finally {
            if (signedFile != null) {
                signedFile.delete();
            }
        }
    }
    
    private void signAndAssertOkMSI(int workerId, int tsId, Date timestamp,
                                boolean rfcTimestamp, boolean clientSide)
            throws Exception {
        File signedFile = null;
        
        try {
            signedFile = signAndAssertOkMSI(msiFile, workerId, tsId, timestamp,
                                            rfcTimestamp, clientSide);
        } finally {
            if (signedFile != null) {
                signedFile.delete();
            }
        }
    }
    
    private void signAndAssertOkAPPX(int workerId, int tsId, Date timestamp,
                                boolean rfcTimestamp, boolean clientSide, Certificate signerCertificate)
            throws Exception {
        File signedFile = null;
        
        try {
            signedFile = signAndAssertOkAPPX(appxFile, workerId, tsId, timestamp,
                                            rfcTimestamp, clientSide, signerCertificate);
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
                                       boolean rfcTimestamp, boolean clientSide)
            throws Exception {
        final File signedFile = File.createTempFile("test-file", ".signed");
        PEFile pe = null;
        
        try {
            // call the CLI
            if (clientSide) {
                assertEquals("Status code", CommandLineInterface.RETURN_SUCCESS,
                        cli.execute("signdocument", "-workerid", Integer.toString(workerId),
                                    "-clientside",
                                    "-infile", sampleFile.getAbsolutePath(),
                                    "-outfile", signedFile.getAbsolutePath(),
                                    "-digestalgorithm", "SHA-256"));
            } else {
                assertEquals("Status code", CommandLineInterface.RETURN_SUCCESS,
                    cli.execute("signdocument", "-workerid", Integer.toString(workerId),
                                "-infile", sampleFile.getAbsolutePath(),
                                "-outfile", signedFile.getAbsolutePath()));
            }
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
                                          boolean rfcTimestamp, boolean clientSide)
            throws Exception {
        final File signedFile = File.createTempFile("test-file", ".signed");

        // call the CLI
        if (clientSide) {
            assertEquals("Status code", CommandLineInterface.RETURN_SUCCESS,
                    cli.execute("signdocument", "-workerid", Integer.toString(workerId),
                                "-clientside",
                                "-infile", sampleFile.getAbsolutePath(),
                                "-outfile", signedFile.getAbsolutePath(),
                                "-digestalgorithm", "SHA-256"));
        } else {
            assertEquals("Status code", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("signdocument", "-workerid", Integer.toString(workerId),
                            "-infile", sampleFile.getAbsolutePath(),
                            "-outfile", signedFile.getAbsolutePath()));
        }

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
    
    /**
     * Submit given APPX file to the signer and assert that the signed file
     * has a DigitalSignature entry and contains a correct timestamp.
     * The checks for the actual signature is done in the unit tests for
     * various algorithms etc.
     * 
     * @param sampleFile
     * @param workerId
     * @param tsId
     * @param timestamp
     * @param rfcTimestamp
     * @param clientSide
     * @param signerCertificate
     * @return
     * @throws Exception 
     */
    public static File signAndAssertOkAPPX(final File sampleFile, int workerId, final int tsId, Date timestamp, boolean rfcTimestamp, boolean clientSide, Certificate signerCertificate)
            throws Exception {
        final File signedFile = File.createTempFile("test-file-signed", ".appx");

        // call the CLI
        if (clientSide) {
            assertEquals("Status code", CommandLineInterface.RETURN_SUCCESS,
                    cli.execute("signdocument", "-workerid", Integer.toString(workerId),
                                "-clientside",
                                "-infile", sampleFile.getAbsolutePath(),
                                "-outfile", signedFile.getAbsolutePath(),
                                "-digestalgorithm", "SHA-256"));
        } else {
            assertEquals("Status code", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("signdocument", "-workerid", Integer.toString(workerId),
                            "-infile", sampleFile.getAbsolutePath(),
                            "-outfile", signedFile.getAbsolutePath()));
        }

        // Extract signature file (CMS)
        byte[] p7xFileContent = null;
        try (final ZipFile file = new ZipFile(signedFile)) {
            final ZipEntry entry = file.getEntry("AppxSignature.p7x");
            final ByteArrayOutputStream bout = new ByteArrayOutputStream();
            IOUtils.copy(file.getInputStream(entry), bout);
            p7xFileContent = bout.toByteArray();
        }
        assertNotNull("extracted AppxSignature.p7x", p7xFileContent);
        
        // First 4 bytes are the magic
        final byte[] p7xMagic = new byte[4];
        System.arraycopy(p7xFileContent, 0, p7xMagic, 0, 4);
        assertEquals("p7x magic", new String(P7X_SIGNATURE, StandardCharsets.US_ASCII), new String(p7xMagic, StandardCharsets.US_ASCII));

        // Get the data after first 4 bytes
        final byte[] signedBytes = new byte[p7xFileContent.length - 4];
        System.arraycopy(p7xFileContent, 4, signedBytes, 0, signedBytes.length);

        final CMSSignedData signedData = new CMSSignedData(signedBytes);

        assertEquals("eContentType SpcIndirectDataContent", "1.3.6.1.4.1.311.2.1.4", signedData.getSignedContentTypeOID());

        final SignerInformation si = (SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();

        // Verify using the signer's certificate (the configured one)
        assertTrue("Verification using signer certificate",
                si.verify(new JcaSignerInfoVerifierBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signerCertificate.getPublicKey())));

        assertTimestampOk(signedData, timestamp, tsId, rfcTimestamp);

        // TODO: Later ticket: Extract the content from the signedData and perform APPX file verification
                
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
