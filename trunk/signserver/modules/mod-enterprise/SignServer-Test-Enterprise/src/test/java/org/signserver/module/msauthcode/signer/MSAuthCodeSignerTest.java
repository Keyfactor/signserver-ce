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
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import net.jsign.DigestAlgorithm;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcPeImageData;
import net.jsign.msi.MSIFile;
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
import net.jsign.script.PowerShellScript;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.apache.poi.poifs.filesystem.DocumentInputStream;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.cli.CommandLineInterface;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.client.cli.ClientCLI;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.module.msauthcode.common.AppxHelper;
import org.signserver.module.msauthcode.common.SpcSipInfo;
import org.signserver.server.FixedTimeSource;
import org.signserver.server.data.impl.CloseableWritableData;
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
    private final File ps1File;
    private final File catFile;

    private static WorkerSessionRemote workerSession = getWorkerSessionS();
    private static ProcessSessionRemote processSession = getProcessSessionS();

    private static final CLITestHelper cli = new CLITestHelper(ClientCLI.class);

    private static final byte[] P7X_SIGNATURE = new byte[] {(byte) 0x50, (byte) 0x4b, (byte) 0x43, (byte) 0x58};

    private enum FileType {
        PE,
        MSI,
        APPX,
        PS1,
        CAT
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
        ps1File = new File(PathUtil.getAppHome(), "res/test/HelloPowerShell.ps1");
        if (!ps1File.exists()) {
            throw new Exception("Missing sample PS1 script: " + ps1File);
        }
        catFile = new File(PathUtil.getAppHome(), "res/test/HelloCat.cat");
        if (!catFile.exists()) {
            throw new Exception("Missing sample CAT file: " + catFile);
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
     */
    @Test
    public void testSigningPEWithInternalTSA() throws Exception {
        signingWithInternalTSA(FileType.PE, null, 1, false);
    }

    /**
     * Tests signing using the SignServer TSA.
     */
    @Test
    public void testSigningCATWithInternalTSA() throws Exception {
        signingWithInternalTSA(FileType.CAT , null, 1, false);
    }

    /**
     * Tests signing using the SignServer TSA. Explicitly specifying to include
     * one certificate in the chain.
     */
    @Test
    public void testSigningCATWithInternalTSAIncludeCertificateLevelsOneExplicit() throws Exception {
        signingWithInternalTSA(FileType.CAT , "1", 1, false);
    }

    /**
     * Tests signing using the SignServer TSA. Specifying two certificates to
     * be included, a higher number than available, should include the available ones.
     */
    @Test
    public void testSigningCATWithInternalTSAIncludeCertificateLevelsTwo() throws Exception {
        signingWithInternalTSA(FileType.CAT , "2", 1, false);
    }

    @Test
    public void testSigningPEWithInternalTSAAndResign() throws Exception {
        signingWithInternalTSA(FileType.PE, null, 1, true);
    }

    /**
     * Tests signing using the SignServer TSA. Explicitly specifying to include
     * one certificate in the chain.
     */
    @Test
    public void testSigningPEWithInternalTSAIncludeCertificateLevelsOneExplicit() throws Exception {
        signingWithInternalTSA(FileType.PE, "1", 1, false);
    }

    /**
     * Tests signing using the SignServer TSA. Specifying two certificates to
     * be included, a higher number than available, should include the available ones.
     */
    @Test
    public void testSigningPEWithInternalTSAIncludeCertificateLevelTwo() throws Exception {
        signingWithInternalTSA(FileType.PE, "2", 1, false);
    }

    /**
     * Test signing when specifying timestamp format with a space, should expect
     * an Authenticode (legacy) TSA.
     */
    @Test
    public void testSigningPEWithInternalTSAExtraSpaceInFormat() throws Exception {
        signingWithInternalTSA(FileType.PE, true, null, 1, false);
    }

    @Test
    public void testSigningMSIWithInternalTSA() throws Exception {
        signingWithInternalTSA(FileType.MSI, null, 1, false);
    }

    /**
     * Test that setting INCLUDE_CERTIFICATE_LEVELS to 0 gives the expected
     * result.
     */
    @Test
    public void testSigningMSIWithInternalTSAIncludeCertificateLevelsZero()
            throws Exception {
        signingWithInternalTSA(FileType.MSI, "0", 0, false);
    }

    /**
     * Test that explicitly setting INCLUDE_CERTIFICATE_LEVELS explicitly to
     * 1 (the number of certs included when not set) still gives the same
     * result.
     */
    @Test
    public void testSigningMSIWithInternalTSAIncludeCertificateLevelsOneExplicit()
            throws Exception {
        signingWithInternalTSA(FileType.MSI, "1", 1, false);
    }

    /**
     * Test that setting INCLUDE_CERTIFICATE_LEVELS to a higher value than the
     * number of available certs still works, and returns the available certs.
     */
    @Test
    public void testSigningMSIWithInternalTSAIncludeCertificateLevelsTwo()
            throws Exception {
        signingWithInternalTSA(FileType.MSI, "2", 1, false);
    }

    private void signingWithInternalTSA(final FileType fileType,
                                        final String includeCertificateLevels,
                                        final int expectedNumCerts,
                                        final boolean doResign)
            throws Exception {
        LOG.info("signingWithInternalTSA");
        signingWithInternalTSA(fileType, false, includeCertificateLevels,
                               expectedNumCerts, doResign);
    }

    /**
     * Tests signing using the SignServer TSA.
     */
    @Test
    public void testSigningAPPXWithInternalTSA() throws Exception {
        signingWithInternalTSA(FileType.APPX, null, 1, false);
    }

    /**
     * Tests signing using the SignServer TSA. Specifying 0 certificates to be included
     * in the chain.
     */
    @Test
    public void testSigningAPPXWithInternalTSAIncludeCertificateLevelsZero() throws Exception {
        signingWithInternalTSA(FileType.APPX, "0", 0, false);
    }

    /**
     * Tests signing using the SignServer TSA. Explicitly specifying one certificate to be included
     * in the chain.
     */
    @Test
    public void testSigningAPPXWithInternalTSAIncludeCertificateLevelsOneExplicit() throws Exception {
        signingWithInternalTSA(FileType.APPX, "1", 1, false);
    }

    /**
     * Tests signing using the SignServer TSA. Specifying 2 certificates to be included
     * in the chain (more than available, included all available).
     */
    @Test
    public void testSigningAPPXWithInternalTSAIncludeCertificateLevelsTwo() throws Exception {
        signingWithInternalTSA(FileType.APPX, "2", 1, false);
    }

    /**
     * Test signing when specifying timestamp format with a space, should expect
     * an Authenticode (legacy) TSA.
     */
    @Test
    public void testSigningAPPXWithInternalTSAExtraSpaceInFormat() throws Exception {
        signingWithInternalTSA(FileType.APPX, true, null, 1, false);
    }

    private void signingWithInternalTSA(final FileType fileType,
                                        final boolean extraSpaceInFormat,
                                        final String includeCertificateLevels,
                                        final int expectedNumCerts,
                                        final boolean doResign)
            throws Exception {
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addMSTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner(fileType == FileType.APPX ? AppxSigner.class.getName() : MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            // test that setting an empty TIMESTAMP_FORMAT actually assumes AUTHENTICODE, as per spec.
            workerSession.setWorkerProperty(WORKER_ID, "TIMESTAMP_FORMAT", extraSpaceInFormat ? " ": "");
            if (includeCertificateLevels != null) {
                workerSession.setWorkerProperty(WORKER_ID,
                                                "INCLUDE_CERTIFICATE_LEVELS",
                                                includeCertificateLevels);
            }
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            switch (fileType) {
                case MSI:
                    signAndAssertOkMSI(TS_ID, time, false, false,
                                       expectedNumCerts);
                    break;
                case PE:
                    if (doResign) {
                        signAndResignAssertOkPE(TS_ID, time, false, false,
                                                expectedNumCerts);
                    } else {
                        signAndAssertOk(TS_ID, time, false, false,
                                        expectedNumCerts);
                    }
                    break;
                case APPX:
                    signAndAssertOkAPPX(TS_ID, time, false, false,
                                        workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)),
                                        expectedNumCerts);
                    break;
                case PS1:
                    signAndAssertOkPs1(TS_ID, time, false, false,
                                       expectedNumCerts);
                    break;
                case CAT:
                    signAndAssertOkCat(TS_ID, time, false, expectedNumCerts);
                    break;
                default:
                    throw new Exception("Test does not handle file type: " + fileType);
            }
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }


    @Test
    public void testSigningPEWithInternalRFCTSA() throws Exception {
        signingWithInternalRFCTSA(FileType.PE, null);
    }

    /**
     * Tests signing CAT file using the SignServer TSA.
     */
    @Test
    public void testSigningCATWithInternalRFCTSA() throws Exception {
        signingWithInternalTSA(FileType.CAT, null, 1, true);
    }

    /**
     * Tests signing a CAT file using the SignServer TSA. Explicitly specifying to include
     * one certificate in the chain.
     */
    @Test
    public void testSigningCATWithInternalRFCTSAIncludeCertificateLevelsOneExplicit() throws Exception {
        signingWithInternalTSA(FileType.CAT , "1", 1, true);
    }

    /**
     * Tests signing a CAT file using the SignServer TSA. Specifying two certificates to
     * be included, a higher number than available, should include the available ones.
     */
    @Test
    public void testSigningCATWithInternalRFCTSAIncludeCertificateLevelsTwo() throws Exception {
        signingWithInternalTSA(FileType.CAT , "2", 1, true);
    }

    @Test
    public void testSigningPEClientSideWithInternalRFCTSA() throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.PE, null, 1, false);
    }

    @Test
    public void testSigningPEClientSideWithInternalRFCTSAAndResign() throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.PE, null, 1, true);
    }

    @Test
    public void testSigningPEClientSideWithInternalRFCTSAIncludeCertificateLevelsZero()
            throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.PE, "0", 0, false);
    }

    @Test
    public void testSigningPEClientSideWithInternalRFCTSAIncludeCertificateLevelsOneExplicit()
            throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.PE, "1", 1, false);
    }

    @Test
    public void testSigningPEClientSideWithInternalRFCTSAIncludeCertificateLevelsTwo()
            throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.PE, "2", 1, false);
    }

    @Test
    public void testSigningMSIWithInternalRFCTSA() throws Exception {
        signingWithInternalRFCTSA(FileType.MSI, null);
    }

    @Test
    public void testSigningMSIClientSideWithInternalRFCTSA() throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.MSI, null, 1, false);
    }

    @Test
    public void testSigningMSIClientSideWithInternalRFCTSAAndResign() throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.MSI, null, 1, true);
    }

    @Test
    public void testSigningMSIClientSideWithInternalRFCTSAIncludeCertificateLevelsZero()
            throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.MSI, "0", 0, false);
    }

    @Test
    public void testSigningMSIClientSideWithInternalRFCTSAIncludeCertificateLevelsOneExplicit()
            throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.MSI, "1", 1, false);
    }

    @Test
    public void testSigningMSIClientSideWithInternalRFCTSAIncludeCertificateLevelsTwo()
            throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.MSI, "2", 1, false);
    }

    @Test
    public void testSigningAPPXWithInternalRFCTSA() throws Exception {
        signingWithInternalRFCTSA(FileType.APPX, null);
    }

    @Test
    public void testSigningAPPXClientSideWithInternalRFCTSA() throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.APPX, null, 1, false);
    }

    @Test
    public void testSigningAPPXClientSideWithInternalRFCTSAIncludeCertificateLevelsZero() throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.APPX, "0", 0, false);
    }

    @Test
    public void testSigningAPPXClientSideWithInternalRFCTSAIncludeCertificateLevelsOneExplicit() throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.APPX, "1", 1, false);
    }

    @Test
    public void testSigningAPPXClientSideWithInternalRFCTSAIncludeCertificateLevelsTwo() throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.APPX, "2", 1, false);
    }

    @Test
    public void testSigningPs1WithInternalRFCTSA() throws Exception {
        signingWithInternalRFCTSA(FileType.PS1, null);
    }

    @Test
    public void testSigningPs1WithInternalRFCTSAIncludeCertificateLevelsOneExplicit()
            throws Exception {
        signingWithInternalRFCTSA(FileType.PS1, "1");
    }

    @Test
    public void testSigningPs1WithInternalRFCTSAIncludeCertificateLevelsTwo()
            throws Exception {
        signingWithInternalRFCTSA(FileType.PS1, "2");
    }

    @Test
    public void testSigningPs1ClientSideWithInternalRFCTSA() throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.PS1, null, 1, false);
    }

    @Test
    public void testSigningPs1ClientSideWithInternalRFCTSAIncludeCertificateLevelsZero()
            throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.PS1, "0", 0, false);
    }

    @Test
    public void testSigningPs1ClientSideWithInternalRFCTSAIncludeCertificateLevelsOneExplicit()
            throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.PS1, "1", 1, false);
    }

    @Test
    public void testSigningPs1ClientSideWithInternalRFCTSAIncludeCertificateLevelsTwo()
            throws Exception {
        signingWithClientHashingInternalRFCTSA(FileType.PS1, "2", 1, false);
    }

    private void signingWithInternalRFCTSA(final FileType fileType,
                                           final String includeCertificateLevels)
            throws Exception {
        LOG.info("signingWithInternalRFCTSA");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_RFC_ID, TS_RFC_NAME, true);
            addSigner(fileType == FileType.APPX ? AppxSigner.class.getName() : MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_RFC_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(WORKER_ID, "TIMESTAMP_FORMAT", "RFC3161");
            if (includeCertificateLevels != null) {
                workerSession.setWorkerProperty(WORKER_ID,
                                                "INCLUDE_CERTIFICATE_LEVELS",
                                                includeCertificateLevels);
            }
            workerSession.setWorkerProperty(TS_RFC_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_RFC_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(TS_RFC_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            switch (fileType) {
                case MSI:
                    signAndAssertOkMSI(TS_RFC_ID, time, true, false,
                            1);
                    break;
                case PE:
                    signAndAssertOk(TS_RFC_ID, time, true, false,
                            1);
                    break;
                case APPX:
                    signAndAssertOkAPPX(TS_RFC_ID, time, true, false,
                                        workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)),
                            1);
                    break;
                case PS1:
                    signAndAssertOkPs1(TS_RFC_ID, time, true, false,
                            1);
                    break;
                case CAT:
                    signAndAssertOkCat(TS_RFC_ID, time, true, 1);
                    break;
                default:
                    throw new Exception("Test does not handle file type: " + fileType);
            }
        } finally {
            removeWorker(TS_RFC_ID);
            removeWorker(WORKER_ID);
        }
    }

    private void signingWithClientHashingInternalRFCTSA(final FileType fileType,
                                                        final String includeCertificateLevels,
                                                        final int expectedNumCerts,
                                                        final boolean doResign)
            throws Exception {
        LOG.info("signingWithInternalRFCTSA");
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_RFC_ID, TS_RFC_NAME, true);
            addSigner(fileType == FileType.APPX ? AppxCMSSigner.class.getName() : MSAuthCodeCMSSigner.class.getName(), WORKER_ID, WORKER_NAME_CMS, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_RFC_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(WORKER_ID, "ALLOW_CLIENTSIDEHASHING_OVERRIDE", "true");
            workerSession.setWorkerProperty(WORKER_ID, "ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256");
            if (includeCertificateLevels != null) {
                workerSession.setWorkerProperty(WORKER_ID,
                                                "INCLUDE_CERTIFICATE_LEVELS",
                                                includeCertificateLevels);
            }
            workerSession.setWorkerProperty(TS_RFC_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_RFC_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(TS_RFC_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            switch (fileType) {
                case MSI:
                    if (doResign) {
                        signAndResignAssertOkMSI(TS_RFC_ID, time, true, true,
                                expectedNumCerts);
                    } else {
                        signAndAssertOkMSI(TS_RFC_ID, time, true, true,
                                expectedNumCerts);
                    }
                    break;
                case PE:
                    if (doResign) {
                        signAndResignAssertOkPE(TS_RFC_ID, time, true, true,
                                                expectedNumCerts);
                    } else {
                        signAndAssertOk(TS_RFC_ID, time, true, true,
                                        expectedNumCerts);
                    }
                    break;
                case APPX:
                    signAndAssertOkAPPX(TS_RFC_ID, time, true, true,
                                        workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)),
                                        expectedNumCerts);
                    break;
                case PS1:
                    signAndAssertOkPs1(TS_RFC_ID, time, true, true,
                                       expectedNumCerts);
                    break;
                default:
                    throw new Exception("Test does not handle file type: " + fileType);
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
     */
    @Test
    public void testSigningPEWithExternalTSA() throws Exception {
        signingWithExternalTSA(FileType.PE);
    }

    @Test
    public void testSigningMSIWithExternalTSA() throws Exception {
        signingWithExternalTSA(FileType.MSI);
    }

    @Test
    public void testSigningAPPXWithExternalTSA() throws Exception {
        signingWithExternalTSA(FileType.APPX);
    }

    @Test
    public void testSigningPS1WithExternalTSA() throws Exception {
        signingWithExternalTSA(FileType.PS1);
    }

    private void signingWithExternalTSA(final FileType fileType) throws Exception {
        LOG.info("signingWithExternalTSA");
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
                    signAndAssertOkMSI(TS_ID, time, false, false,
                            1);
                    break;
                case PE:
                    signAndAssertOk(TS_ID, time, false, false,
                            1);
                    break;
                case APPX:
                    signAndAssertOkAPPX(TS_ID, time, false, false,
                                        workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)),
                            1);
                    break;
                case PS1:
                    signAndAssertOkPs1(TS_ID, time, false, false,
                            1);
                    break;
                default:
                    throw new Exception("Test does not handle file type: " + fileType);
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
     */
    @Test
    public void testSigningPEWithExternalRFCTSA() throws Exception {
        signingWithExternalRFCTSA(FileType.PE);
    }

    @Test
    public void testSigningPEClientSideWithExternalRFCTSA() throws Exception {
        signingWithClientHashingExternalRFCTSA(FileType.PE);
    }

    @Test
    public void testSigningMSIWithExternalRFCTSA() throws Exception {
        signingWithExternalRFCTSA(FileType.MSI);
    }

    @Test
    public void testSigningMSIClientSideWithExternalRFCTSA() throws Exception {
        signingWithClientHashingExternalRFCTSA(FileType.MSI);
    }

    @Test
    public void testSigningPs1WithExternalRFCTSA() throws Exception {
        signingWithExternalRFCTSA(FileType.PS1);
    }

    @Test
    public void testSigningPs1ClientSideWithExternalRFCTSA() throws Exception {
        signingWithClientHashingExternalRFCTSA(FileType.PS1);
    }

    @Test
    public void testSigningAPPXWithExternalRFCTSA() throws Exception {
        signingWithExternalRFCTSA(FileType.APPX);
    }

    @Test
    public void testSigningAPPXClientSideWithExternalRFCTSA() throws Exception {
        signingWithClientHashingExternalRFCTSA(FileType.APPX);
    }

    private void signingWithExternalRFCTSA(final FileType fileType) throws Exception {
        LOG.info("signingWithExternalTSA");
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
                    signAndAssertOkMSI(TS_RFC_ID, time, true, false,
                            1);
                    break;
                case PE:
                    signAndAssertOk(TS_RFC_ID, time, true, false,
                            1);
                    break;
                case APPX:
                    signAndAssertOkAPPX(TS_RFC_ID, time, true, false,
                                        workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)),
                            1);
                    break;
                case PS1:
                    signAndAssertOkPs1(TS_RFC_ID, time, true, false,
                            1);
                    break;
                default:
                    throw new Exception("Test does not handle file type: " + fileType);
            }
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_RFC_ID);
        }
    }

    private void signingWithClientHashingExternalRFCTSA(final FileType fileType) throws Exception {
        LOG.info("signingWithClientHashingExternalTSA");
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
                    signAndAssertOkMSI(TS_RFC_ID, time, true, true,
                            1);
                    break;
                case PE:
                    signAndAssertOk(TS_RFC_ID, time, true, true,
                            1);
                    break;
                case APPX:
                    signAndAssertOkAPPX(TS_RFC_ID, time, true, true,
                                        workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)),
                            1);
                    break;
                case PS1:
                    signAndAssertOkPs1(TS_RFC_ID, time, true, true,
                            1);
                    break;
                default:
                    throw new Exception("Test does not handle file type: " + fileType);
            }
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_RFC_ID);
        }
    }

    /**
     * Tests username/password authentication for internal TSA.
     */
    @Test
    public void testSigningPEWithInternalTSA_auth() throws Exception {
        signingWithInternalTSA_auth(FileType.PE);
    }

    @Test
    public void testSigningMSIWithInternalTSA_auth() throws Exception {
        signingWithInternalTSA_auth(FileType.MSI);
    }

    @Test
    public void testSigningAPPXWithInternalTSA_auth() throws Exception {
        signingWithInternalTSA_auth(FileType.APPX);
    }

    @Test
    public void testSigningPs1WithInternalTSA_auth() throws Exception {
        signingWithInternalTSA_auth(FileType.PS1);
    }


    private void signingWithInternalTSA_auth(final FileType fileType) throws Exception {
        LOG.info("signingWithInternalTSA_auth");
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
                    signAndAssertOkMSI(TS_ID, time, false, false,
                            1);
                    break;
                case PE:
                    signAndAssertOk(TS_ID, time, false, false,
                            1);
                    break;
                case APPX:
                    signAndAssertOkAPPX(TS_ID, time, false, false,
                                        workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)),
                            1);
                    break;
                case PS1:
                    signAndAssertOkPs1(TS_ID, time, false, false,
                            1);
                    break;
                default:
                    throw new Exception("Test does not handle file type: " + fileType);
            }
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }

    /**
     * Tests username/password authentication for internal RFC 3161 TSA.
     */
    @Test
    public void testSigningPEWithInternalRFCTSA_auth() throws Exception {
        signingWithInternalRFCTSA_auth(FileType.PE);
    }

    @Test
    public void testSigningMSIWithInternalRFCTSA_auth() throws Exception {
        signingWithInternalRFCTSA_auth(FileType.MSI);
    }

    private void signingWithInternalRFCTSA_auth(final FileType fileType) throws Exception {
        LOG.info("signingWithInternalTSA_auth");
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
                    signAndAssertOkMSI(TS_RFC_ID, time, true, false,
                            1);
                    break;
                case PE:
                    signAndAssertOk(TS_RFC_ID, time, true, false,
                            1);
                    break;
                case APPX:
                    signAndAssertOkAPPX(TS_RFC_ID, time, true, false,
                                        workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)),
                            1);
                    break;
                default:
                    throw new Exception("Test does not handle file type: " + fileType);
            }
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_RFC_ID);
        }
    }

    /**
     * Tests username/password authentication for external TSA.
     */
    @Test
    public void testSigningPEWithExternalTSA_auth()
            throws Exception {
        signingWithExternalTSA_auth(FileType.PE);
    }

    @Test
    public void testSigningMSIWithExternalTSA_auth()
            throws Exception {
        signingWithExternalTSA_auth(FileType.MSI);
    }

    @Test
    public void testSigningAPPXWithExternalTSA_auth()
            throws Exception {
        signingWithExternalTSA_auth(FileType.APPX);
    }

    private void signingWithExternalTSA_auth(final FileType fileType) throws Exception {
        LOG.info("signingWithExternalTSA");
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
                    signAndAssertOkMSI(TS_ID, time, false, false,
                            1);
                    break;
                case PE:
                    signAndAssertOk(TS_ID, time, false, false,
                            1);
                    break;
                case APPX:
                    signAndAssertOkAPPX(TS_ID, time, false, false,
                                        workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)),
                            1);
                    break;
                default:
                    throw new Exception("Test does not handle file type: " + fileType);
            }
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }

    /**
     * Tests username/password authentication for external RFC 3161 TSA.
     */
    @Test
    public void testSigningPEWithExternalRFCTSA_auth()
            throws Exception {
        signingWithExternalRFCTSA_auth(FileType.PE);
    }

    @Test
    public void testSigningMSIWithExternalRFCTSA_auth()
            throws Exception {
        signingWithExternalRFCTSA_auth(FileType.MSI);
    }

    @Test
    public void testSigningAPPXWithExternalRFCTSA_auth()
            throws Exception {
        signingWithExternalRFCTSA_auth(FileType.APPX);
    }

    private void signingWithExternalRFCTSA_auth(final FileType fileType) throws Exception {
        LOG.info("signingWithExternalTSA");
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
                    signAndAssertOkMSI(TS_RFC_ID, time, true, false,
                            1);
                    break;
                case PE:
                    signAndAssertOk(TS_RFC_ID, time, true, false,
                            1);
                    break;
                case APPX:
                    signAndAssertOkAPPX(TS_RFC_ID, time, true, false,
                                        workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)),
                            1);
                    break;
                default:
                    throw new Exception("Test does not handle file type: " + fileType);
            }
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_RFC_ID);
        }
    }

    /**
     * Tests that incorrect TSA password gives error for external TSA.
     */
    @Test
    public void testSigningPEWithExternalTSA_authWrong() throws Exception {
        signingWithExternalTSA_authWrong(FileType.PE);
    }

    @Test
    public void testSigningMSIWithExternalTSA_authWrong() throws Exception {
        signingWithExternalTSA_authWrong(FileType.MSI);
    }

    @Test
    public void testSigningAPPXWithExternalTSA_authWrong() throws Exception {
        signingWithExternalTSA_authWrong(FileType.APPX);
    }

    private void signingWithExternalTSA_authWrong(final FileType fileType) throws Exception {
        LOG.info("signingWithExternalTSA");
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

            signAndAssertFailed(file);
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }

    /**
     * Tests that incorrect TSA password gives error for internal TSA.
     */
    @Test
    public void testSigningPEWithInternalTSA_authWrong() throws Exception {
        signingWithInternalTSA_authWrong(FileType.PE);
    }

    @Test
    public void testSigningMSIWithInternalTSA_authWrong() throws Exception {
        signingWithInternalTSA_authWrong(FileType.MSI);
    }

    @Test
    public void testSigningAPPXWithInternalTSA_authWrong() throws Exception {
        signingWithInternalTSA_authWrong(FileType.APPX);
    }

    private void signingWithInternalTSA_authWrong(final FileType fileType) throws Exception {
        LOG.info("signingWithInternalTSA_auth");
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

            signAndAssertFailed(file);
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }

    private void signAndAssertOk(final int tsId,
                                 final Date timestamp,
                                 final boolean rfcTimestamp,
                                 final boolean clientSide,
                                 final int expectedNumCerts)
            throws Exception {
        File signedFile = null;

        try {
            signedFile = signAndAssertOk(executableFile, WORKER_ID,
                        tsId, timestamp, rfcTimestamp, clientSide,
                        expectedNumCerts);
        } finally {
            if (signedFile != null) {
                signedFile.delete();
            }
        }
    }

    private void signAndAssertOkMSI(final int tsId,
                                    final Date timestamp,
                                    final boolean rfcTimestamp,
                                    final boolean clientSide,
                                    final int expectedNumCerts)
            throws Exception {
        File signedFile = null;

        try {
            signedFile = signAndAssertOkMSI(msiFile, WORKER_ID, tsId, timestamp,
                                            rfcTimestamp, clientSide,
                                            expectedNumCerts);
        } finally {
            if (signedFile != null) {
                signedFile.delete();
            }
        }
    }

    private void signAndAssertOkAPPX(final int tsId,
                                     final Date timestamp,
                                     final boolean rfcTimestamp,
                                     final boolean clientSide,
                                     final Certificate signerCertificate,
                                     final int expectedNumCerts)
            throws Exception {
        File signedFile = null;

        try {
            signedFile = signAndAssertOkAPPX(appxFile, WORKER_ID, tsId, timestamp,
                                             rfcTimestamp, clientSide,
                                             signerCertificate, "SHA-256",
                                             expectedNumCerts);
        } finally {
            if (signedFile != null) {
                signedFile.delete();
            }
        }
    }

    private void signAndAssertOkPs1(final int tsId,
                                    final Date timestamp,
                                    final boolean rfcTimestamp,
                                    final boolean clientSide,
                                    final int expectedNumCerts)
            throws Exception {
        File signedFile = null;

        try {
            signedFile = signAndAssertOkPs1(ps1File, MSAuthCodeSignerTest.WORKER_ID,
                        tsId, timestamp, rfcTimestamp, clientSide,
                        expectedNumCerts);
        } finally {
            if (signedFile != null) {
                signedFile.delete();
            }
        }
    }

    private void signAndAssertOkCat(final int tsId,
                                    final Date timestamp,
                                    final boolean rfcTimestamp,
                                    final int expectedNumCerts)
            throws Exception {
        File signedFile = null;

        try {
            signedFile = signAndAssertOkCat(catFile, MSAuthCodeSignerTest.WORKER_ID,
                        tsId, timestamp, rfcTimestamp, expectedNumCerts);
        } finally {
            if (signedFile != null) {
                signedFile.delete();
            }
        }
    }

    /**
     * Tests an expected failed signing (used by TSA auth failed tests).
     */
    private void signAndAssertFailed(final File file) throws Exception {
        try {
            RemoteRequestContext requestContext = new RemoteRequestContext();
            byte[] sampleFile = FileUtils.readFileToByteArray(file);
            GenericSignRequest request = new GenericSignRequest(100, sampleFile);
            processSession.process(new WorkerIdentifier(WORKER_ID), request, requestContext);
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
     * @param clientSide If client-side hashing should be used
     * @param expectedNumCerts Number of certificates expected to be included in the chain
     * @return the signed binary
     * @throws java.lang.Exception
     */
    public static File signAndAssertOk(final File sampleFile, int workerId,
                                       final int tsId, final Date timestamp,
                                       final boolean rfcTimestamp,
                                       final boolean clientSide,
                                       final int expectedNumCerts)
            throws Exception {
        final File signedFile = createTempOutputFile(sampleFile);
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

            final CMSSignedData cms = signatures.get(0);

            assertSignedDataPE(cms, pe, expectedNumCerts, tsId, timestamp,
                             rfcTimestamp);

            return signedFile;
        } finally {
            if (pe != null) {
                pe.close();
            }
        }
    }

    /**
     * Test signing a PE file once, verifying the signature. Then resigns
     * the file and verifies that there is a new signature and that the binary
     * can be verified using both signatures.
     * 
     * @param sampleFile File to sign
     * @param workerId Worker ID of signer
     * @param tsId Worker ID for internal timestamp signer
     * @param timestamp Hard-coded time used by the timestamp (using the mock timesource)
     * @param rfcTimestamp True if RFC 3161 timestamp format should be used
     * @param clientSide True if client-side mode is to be used for signing
     *                   (assumes an MSAuthCodeCMSSigner)
     * @param expectedNumCerts Expected number of certificates included
     *                         in the signatures
     * @throws IOException
     * @throws UnexpectedCommandFailureException
     * @throws CMSException
     * @throws TSPException
     * @throws CryptoTokenOfflineException
     * @throws CertificateException 
     */
    static File signAndResignAssertOkPE(final File sampleFile,
                                        int workerId,
                                        final int tsId,
                                        final Date timestamp,
                                        final boolean rfcTimestamp,
                                        final boolean clientSide,
                                        final int expectedNumCerts)
            throws IOException, UnexpectedCommandFailureException, CMSException,
                   TSPException, CryptoTokenOfflineException,
                   CertificateException {
        final File signedFile = createTempOutputFile(sampleFile);
        final File resignedFile = createTempOutputFile(signedFile);
        PEFile pe = null;
        PEFile resignedPe = null;

        try {
            // call the CLI
            signFileUsingCli(sampleFile, signedFile, clientSide, workerId);
            pe = new PEFile(signedFile);

            List<CMSSignedData> signatures = pe.getSignatures();
            assertEquals("Number of signatures", 1, signatures.size());

            final CMSSignedData cms = signatures.get(0);

            assertSignedDataPE(cms, pe, expectedNumCerts, tsId, timestamp,
                               rfcTimestamp);

            // sign the already signed file
            signFileUsingCli(signedFile, resignedFile, clientSide, workerId);
            resignedPe = new PEFile(resignedFile);

            signatures = resignedPe.getSignatures();
            assertEquals("Number of signatures after resigning", 2,
                         signatures.size());

            final CMSSignedData oldCms = signatures.get(0);
            final CMSSignedData newCms = signatures.get(1);

            assertSignedDataPE(oldCms, resignedPe, expectedNumCerts, tsId,
                               timestamp, rfcTimestamp);
            assertSignedDataPE(newCms, resignedPe, expectedNumCerts, tsId,
                               timestamp, rfcTimestamp);

            return resignedFile;
        } finally {
            if (pe != null) {
                pe.close();
            }

            if (resignedPe != null) {
                resignedPe.close();
            }

            signedFile.delete();
        }
    }

    static File signAndResignAssertOkMSI(final File sampleFile,
                                        int workerId,
                                        final int tsId,
                                        final Date timestamp,
                                        final boolean rfcTimestamp,
                                        final boolean clientSide,
                                        final int expectedNumCerts)
            throws IOException, UnexpectedCommandFailureException, CMSException,
            TSPException, CryptoTokenOfflineException,
            CertificateException {
        final File signedFile = createTempOutputFile(sampleFile);
        final File resignedFile = createTempOutputFile(signedFile);
        MSIFile msiFile = null;
        MSIFile resignedMsi = null;

        try {
            // call the CLI
            signFileUsingCli(sampleFile, signedFile, clientSide, workerId);
            msiFile = new MSIFile(signedFile);

            List<CMSSignedData> signatures = msiFile.getSignatures();
            assertEquals("Number of signatures", 1, signatures.size());

            final CMSSignedData cms = signatures.get(0);

            assertSignedDataMSI(cms, msiFile, expectedNumCerts, tsId, timestamp,
                    rfcTimestamp);

            // sign the already signed file
            signFileUsingCli(signedFile, resignedFile, clientSide, workerId);
            resignedMsi = new MSIFile(resignedFile);

            signatures = resignedMsi.getSignatures();
            assertEquals("Number of signatures after resigning", 2,
                    signatures.size());

            final CMSSignedData oldCms = signatures.get(0);
            final CMSSignedData newCms = signatures.get(1);

            assertSignedDataMSI(oldCms, resignedMsi, expectedNumCerts, tsId,
                    timestamp, rfcTimestamp);
            assertSignedDataMSI(newCms, resignedMsi, expectedNumCerts, tsId,
                    timestamp, rfcTimestamp);

            return resignedFile;
        } finally {
            if (msiFile != null) {
                msiFile.close();
            }

            if (resignedMsi != null) {
                resignedMsi.close();
            }

            signedFile.delete();
        }
    }

    private void signAndResignAssertOkPE(final int tsId,
                                         final Date timestamp,
                                         final boolean rfcTimestamp,
                                         final boolean clientSide,
                                         final int expectedNumCerts)
            throws Exception {
        File resignedFile = null;

        try {
            resignedFile = signAndResignAssertOkPE(executableFile, WORKER_ID,
                        tsId, timestamp, rfcTimestamp, clientSide,
                        expectedNumCerts);
        } finally {
            if (resignedFile != null) {
                resignedFile.delete();
            }
        }
    }
    private void signAndResignAssertOkMSI(final int tsId,
                                         final Date timestamp,
                                         final boolean rfcTimestamp,
                                         final boolean clientSide,
                                         final int expectedNumCerts)
            throws Exception {
        File resignedFile = null;

        try {
            resignedFile = signAndResignAssertOkMSI(msiFile, WORKER_ID,
                    tsId, timestamp, rfcTimestamp, clientSide,
                    expectedNumCerts);
        } finally {
            if (resignedFile != null) {
                resignedFile.delete();
            }
        }
    }

    private static void signFileUsingCli(final File inFile,
                                         final File outFile,
                                         final boolean clientSide,
                                         final int workerId)
            throws UnexpectedCommandFailureException, IOException {
        if (clientSide) {
            assertEquals("Status code", CommandLineInterface.RETURN_SUCCESS,
                    cli.execute("signdocument", "-workerid", Integer.toString(workerId),
                                "-clientside",
                                "-infile", inFile.getAbsolutePath(),
                                "-outfile", outFile.getAbsolutePath(),
                                "-digestalgorithm", "SHA-256"));
        } else {
            assertEquals("Status code", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("signdocument", "-workerid", Integer.toString(workerId),
                            "-infile", inFile.getAbsolutePath(),
                            "-outfile", outFile.getAbsolutePath()));
        }
    }

    /**
     * Assert that a signature from a PE file can be verified.
     * 
     * @param cms Signed data to verify
     * @param pe Original PE file
     * @param expectedNumCerts expected number of included certificates
     * @param tsId Worker ID of timestamp signer
     * @param timestamp Time when the timestamp was issued
     * @param rfcTimestamp True if the timestamp format uses RFC 3161,
     *                     otherwise assume legacy Authenticode format
     * @throws IOException
     * @throws CMSException
     * @throws TSPException
     * @throws CryptoTokenOfflineException
     * @throws CertificateException 
     */
    private static void assertSignedDataPE(final CMSSignedData cms,
                                  final PEFile pe,
                                  final int expectedNumCerts,
                                  final int tsId, final Date timestamp,
                                  final boolean rfcTimestamp)
            throws IOException, CMSException, TSPException,
                   CryptoTokenOfflineException, CertificateException {
        Store<X509CertificateHolder> certStore = cms.getCertificates();

        // Get signers
        final Collection<SignerInformation> signers = cms.getSignerInfos().getSigners();
        final SignerInformation signer = signers.iterator().next();

        final SignerId sid = signer.getSID();
        final Selector certSelector =
            new AttributeCertificateHolder(sid.getIssuer(),
                                           sid.getSerialNumber());
        final Collection<? extends X509CertificateHolder> signerCerts =
            certStore.getMatches(certSelector);
        assertEquals("Number of certificates", expectedNumCerts,
                     signerCerts.size());

        // Log the size of the signature
        final byte[] signatureFieldValue = cms.getEncoded();
        LOG.info("Signature size: " + signatureFieldValue.length);

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
        final CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(content), signatureFieldValue);

        assertTimestampOk(signedData, timestamp, tsId, rfcTimestamp);
    }

    /**
     * Assert that a signature from a MSI file can be verified.
     *
     * @param cms Signed data to verify
     * @param msiFile Original MSI file
     * @param expectedNumCerts expected number of included certificates
     * @param tsId Worker ID of timestamp signer
     * @param timestamp Time when the timestamp was issued
     * @param rfcTimestamp True if the timestamp format uses RFC 3161,
     *                     otherwise assume legacy Authenticode format
     * @throws IOException
     * @throws CMSException
     * @throws TSPException
     * @throws CryptoTokenOfflineException
     * @throws CertificateException
     */
    private static void assertSignedDataMSI(final CMSSignedData cms,
                                           final MSIFile msiFile,
                                           final int expectedNumCerts,
                                           final int tsId, final Date timestamp,
                                           final boolean rfcTimestamp)
            throws IOException, CMSException, TSPException,
            CryptoTokenOfflineException, CertificateException {
        Store<X509CertificateHolder> certStore = cms.getCertificates();

        // Get signers
        final Collection<SignerInformation> signers = cms.getSignerInfos().getSigners();
        final SignerInformation signer = signers.iterator().next();

        final SignerId sid = signer.getSID();
        final Selector certSelector =
                new AttributeCertificateHolder(sid.getIssuer(),
                        sid.getSerialNumber());
        final Collection<? extends X509CertificateHolder> signerCerts =
                certStore.getMatches(certSelector);
        assertEquals("Number of certificates", expectedNumCerts,
                signerCerts.size());

        // Log the size of the signature
        final byte[] signatureFieldValue = cms.getEncoded();
        LOG.info("Signature size: " + signatureFieldValue.length);

        // Reconstruct the data "to be signed"

        DigestAlgorithm digestAlg = DigestAlgorithm.of("SHA1");
        byte[] sha1 = msiFile.computeDigest(digestAlg.getMessageDigest());
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(X509ObjectIdentifiers.id_SHA1, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, sha1);
        SpcAttributeTypeAndOptionalValue sataov =
                new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID,
                        new SpcPeImageData());
        SpcIndirectDataContent spcIndirectDataContent =
                new SpcIndirectDataContent(sataov, digestInfo);
        final byte[] idcBytes = spcIndirectDataContent.toASN1Primitive().getEncoded("DER");
        final byte[] content = new byte[idcBytes.length - 2];
        System.arraycopy(idcBytes, 2, content, 0, idcBytes.length - 2);

        // SignedData with the content-to-be-signed filled in
        final CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(content), signatureFieldValue);

        assertTimestampOk(signedData, timestamp, tsId, rfcTimestamp);
    }

    /**
     * Create a new temp output file with an appropriate file name.
     *
     * The file name for ORIGINAL.FILE could for instance be:
     * output-ORIGINAL.FILE-1234567890.FILE
     *
     * And the file name for ORIGINAL could for instance be:
     * output-ORIGINAL-1234567890.tmp
     *
     * Note: Remember to remove the file!
     *
     * @param originalFile to base the new file name on
     * @return The created temp file
     */
    public static File createTempOutputFile(final File originalFile) throws IOException {
        final String fileEnding;
        final String original = originalFile.getName();
        int lastDot = original.lastIndexOf('.');
        if (lastDot >= 0 && lastDot < original.length()) {
            fileEnding = original.substring(lastDot);
        } else {
            fileEnding = ".tmp";
        }

        return File.createTempFile("output-" + original + "-", fileEnding);
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
     * @param clientSide if client-side hashing should be used
     * @param expectedNumCerts expected number of certificates returned in the chain
     * @return the signed binary
     */
    public static File signAndAssertOkPs1(final File sampleFile,
                                          final int workerId,
                                          final int tsId,
                                          final Date timestamp,
                                          final boolean rfcTimestamp,
                                          final boolean clientSide,
                                          final int expectedNumCerts)
            throws Exception {
        final File signedFile = createTempOutputFile(sampleFile);
        PowerShellScript ps1;

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
        ps1 = new PowerShellScript(signedFile);

        List<CMSSignedData> signatures = ps1.getSignatures();
        assertEquals("Number of signatures", 1, signatures.size());

        final CMSSignedData cms = signatures.get(0);
        Store<X509CertificateHolder> certStore = cms.getCertificates();

        // Get signers
        final Collection<SignerInformation> signers = cms.getSignerInfos().getSigners();
        final SignerInformation signer = signers.iterator().next();

        final SignerId sid = signer.getSID();
        final Selector certSelector =
            new AttributeCertificateHolder(sid.getIssuer(),
                                           sid.getSerialNumber());
        final Collection<? extends X509CertificateHolder> signerCerts =
            certStore.getMatches(certSelector);
        assertEquals("Number of certificates", expectedNumCerts,
                     signerCerts.size());

        // Log the size of the signature
        final byte[] signatureFieldValue = cms.getEncoded();
        LOG.info("Signature size: " + signatureFieldValue.length);

        // Reconstruct the data "to be signed"
        DigestAlgorithm digestAlg = DigestAlgorithm.of("SHA1");
        ASN1Object spcIndirectDataContent = ps1.createIndirectData(digestAlg);

        final byte[] idcBytes = spcIndirectDataContent.toASN1Primitive().getEncoded("DER");
        final byte[] content = new byte[idcBytes.length - 2]; // XXX: this assumes 2 bytes for the ASN.1 encoding and might not work for SHA-512 or larger structures. See how it is done in a better way in other places
        System.arraycopy(idcBytes, 2, content, 0, idcBytes.length - 2);

        // SignedData with the content-to-be-signed filled in
        final CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(content), signatureFieldValue);

        assertTimestampOk(signedData, timestamp, tsId, rfcTimestamp);

        return signedFile;
    }

    /**
     * Submit given MSI file to the signer and assert that the signed file
     * has a DigitalSignature entry and contains a correct timestamp.The checks for the actual signature is done in the unit tests for
 various algorithms etc.
     *
     * @param sampleFile sample file
     * @param workerId worker id
     * @param tsId ts id
     * @param timestamp timestamp
     * @param rfcTimestamp rfc timestamp
     * @param clientSide if client side hashing should be used
     * @param expectedNumCerts the number of certs expected to be included in the chain
     * @return file
     */
    public static File signAndAssertOkMSI(final File sampleFile, final int workerId,
                                          final int tsId, final Date timestamp,
                                          final boolean rfcTimestamp,
                                          final boolean clientSide,
                                          final int expectedNumCerts)
            throws Exception {
        final File signedFile = createTempOutputFile(sampleFile);

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

                Store<X509CertificateHolder> certStore = cms.getCertificates();

                // Get signers
                final Collection<SignerInformation> signers = cms.getSignerInfos().getSigners();
                final SignerInformation signer = signers.iterator().next();

                final SignerId sid = signer.getSID();
                final Selector certSelector =
                    new AttributeCertificateHolder(sid.getIssuer(),
                                                   sid.getSerialNumber());
                final Collection<? extends X509CertificateHolder> signerCerts =
                    certStore.getMatches(certSelector);
                assertEquals("Number of certificates", expectedNumCerts,
                             signerCerts.size());
                assertTimestampOk(cms, timestamp, tsId, rfcTimestamp);
            }
        }

        return signedFile;
    }

    public static File signAndAssertOkCat(final File sampleFile, final int workerId,
                                          final int tsId, final Date timestamp,
                                          final boolean rfcTimestamp,
                                          final int expectedNumCerts)
            throws Exception {
        final File signedFile = createTempOutputFile(sampleFile);

        // call the CLI
        assertEquals("Status code", CommandLineInterface.RETURN_SUCCESS,
            cli.execute("signdocument", "-workerid", Integer.toString(workerId),
                        "-infile", sampleFile.getAbsolutePath(),
                        "-outfile", signedFile.getAbsolutePath()));


        final byte[] buf = FileUtils.readFileToByteArray(signedFile);
        final CMSSignedData cms = new CMSSignedData(buf);

        Store<X509CertificateHolder> certStore = cms.getCertificates();

        // Get signers
        final Collection<SignerInformation> signers = cms.getSignerInfos().getSigners();
        final SignerInformation signer = signers.iterator().next();

        final SignerId sid = signer.getSID();
        final Selector certSelector =
            new AttributeCertificateHolder(sid.getIssuer(),
                                           sid.getSerialNumber());
        final Collection<? extends X509CertificateHolder> signerCerts =
            certStore.getMatches(certSelector);
        assertEquals("Number of certificates", expectedNumCerts,
                     signerCerts.size());
        assertTimestampOk(cms, timestamp, tsId, rfcTimestamp);

        return signedFile;
    }

    /**
     * Submit given APPX file to the signer and assert that the signed file
     * has a DigitalSignature entry and contains a correct timestamp.The checks for the actual signature is done in the unit tests for
 various algorithms etc.
     *
     * @param sampleFile sample file
     * @param workerId worker id
     * @param tsId td is
     * @param timestamp timestamp
     * @param rfcTimestamp rfc timestamp
     * @param clientSide client side
     * @param signerCertificate signer certificate
     * @param digestAlgorithmString digest algorithm string
     * @param expectedNumCerts expected number of certificates
     */
    public static File signAndAssertOkAPPX(final File sampleFile,
                                           final int workerId, final int tsId,
                                           final Date timestamp,
                                           final boolean rfcTimestamp,
                                           final boolean clientSide,
                                           final Certificate signerCertificate,
                                           final String digestAlgorithmString,
                                           final int expectedNumCerts)
            throws Exception {
        final File signedFile = File.createTempFile("test-file-signed", ".appx");

        // call the CLI
        if (clientSide) {
            assertEquals("Status code", CommandLineInterface.RETURN_SUCCESS,
                    cli.execute("signdocument", "-workerid", Integer.toString(workerId),
                                "-clientside",
                                "-infile", sampleFile.getAbsolutePath(),
                                "-outfile", signedFile.getAbsolutePath(),
                                "-digestalgorithm", digestAlgorithmString));
        } else {
            assertEquals("Status code", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("signdocument", "-workerid", Integer.toString(workerId),
                            "-infile", sampleFile.getAbsolutePath(),
                            "-outfile", signedFile.getAbsolutePath()));
        }

        // Extract signature file (CMS)
        byte[] p7xFileContent;
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

        Store<X509CertificateHolder> certStore = signedData.getCertificates();

        // Get signers
        final Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        final SignerInformation signer = signers.iterator().next();

        final SignerId sid = signer.getSID();
        final Selector certSelector =
            new AttributeCertificateHolder(sid.getIssuer(),
                                           sid.getSerialNumber());
        final Collection<? extends X509CertificateHolder> signerCerts =
            certStore.getMatches(certSelector);
        assertEquals("Number of certificates", expectedNumCerts,
                     signerCerts.size());

        assertEquals("eContentType SpcIndirectDataContent", "1.3.6.1.4.1.311.2.1.4", signedData.getSignedContentTypeOID());

        final SignerInformation si = (SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();

        // Verify using the signer's certificate (the configured one)
        assertTrue("Verification using signer certificate",
                si.verify(new JcaSignerInfoVerifierBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signerCertificate.getPublicKey())));

        assertTimestampOk(signedData, timestamp, tsId, rfcTimestamp);

        // Extract the content from the signedData and perform APPX file verification
        final SpcIndirectDataContent idcFromSignature = SpcIndirectDataContent.getInstance((ASN1Sequence) signedData.getSignedContent().getContent());
        LOG.info("Digest from signature: " + Hex.toHexString(idcFromSignature.messageDigest.getDigest()));

        // Calculate digest of file and verify the content
        try (
            RandomAccessFile rafInput = new RandomAccessFile(signedFile, "r");
            CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            RandomAccessFile rafOutput = new RandomAccessFile(responseData.getAsFile(), "rw");
        ) {
            final DigestAlgorithm expectedDigestAlgorithm = DigestAlgorithm.of(digestAlgorithmString);
            if (expectedDigestAlgorithm == null) {
                throw new NoSuchAlgorithmException(digestAlgorithmString);
            }

            final byte[] byteArrDigest = AppxHelper.calculateDigestForVerification(rafInput, rafOutput, expectedDigestAlgorithm.oid.getId());
            LOG.info("Digest calculate from file: " + Hex.toHexString(byteArrDigest));

            final SpcSipInfo sipInfo = MSAuthCodeUtils.createAppxSpcSipInfo();
            final SpcIndirectDataContent idcCalculated = new SpcIndirectDataContent(new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID, sipInfo), new DigestInfo(new AlgorithmIdentifier(expectedDigestAlgorithm.oid, DERNull.INSTANCE), byteArrDigest));

            assertEquals("idc algorithm id", idcCalculated.messageDigest.getAlgorithmId().getAlgorithm().getId(), idcFromSignature.messageDigest.getAlgorithmId().getAlgorithm().getId());
            assertEquals("idc digest value", Hex.toHexString(idcCalculated.messageDigest.getDigest()), Hex.toHexString(idcFromSignature.messageDigest.getDigest()));
        }

        return signedFile;
    }

    private static void assertTimestampOk(final CMSSignedData signedData,
                                   final Date timestamp,
                                   final int tsId,
                                   final boolean rfcTimestamp)
            throws IOException, TSPException, CMSException,
                   CryptoTokenOfflineException, CertificateException {
        final SignerInformation si = signedData.getSignerInfos().getSigners().iterator().next();

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

            Collection<SignerInformation> signers = counterSignature.getSigners();
            assertEquals(1, signers.size());
            SignerInformation si2 = signers.iterator().next();

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

    /**
     * Tests signing and checksum calculation.
     */
    @Test
    public void testSigningPeAndChecksum_serverSide() throws Exception {
        try {
            addSigner(MSAuthCodeSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.reloadConfiguration(WORKER_ID);

            File signedFile = null;
            try {
                signedFile = signPeAndAssertChecksum(executableFile, WORKER_ID, false);
            } finally {
                if (signedFile != null) {
                    signedFile.delete();
                }
            }

        } finally {
            removeWorker(WORKER_ID);
        }
    }

//    /**
//     * Tests signing and checksum calculation.
//     * @throws Exception
//     */
//    This test does not work until jsign-core.jar is updated in the Maven repository
//    @Test
//    public void testSigningPeAndChecksum_clientSide() throws Exception {
//        try {
//            addSigner(MSAuthCodeCMSSigner.class.getName(), WORKER_ID, WORKER_NAME_CMS, true);
//            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
//            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
//            workerSession.setWorkerProperty(WORKER_ID, "ALLOW_CLIENTSIDEHASHING_OVERRIDE", "true");
//            workerSession.setWorkerProperty(WORKER_ID, "ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256");
//            workerSession.reloadConfiguration(WORKER_ID);
//
//            File signedFile = null;
//            try {
//                signedFile = signPeAndAssertChecksum(executableFile, WORKER_ID, true);
//            } finally {
//                if (signedFile != null) {
//                    signedFile.delete();
//                }
//            }
//
//        } finally {
//            removeWorker(WORKER_ID);
//        }
//    }

    /**
     * Submits the given portable executable to the signer and
     * then checks that the signature seems to be made by the right signer
     * and that the checksum field has been updated and matches the calculated
     * value.
     * This is a test for DSS-2177.
     *
     * @param sampleFile binary to sign
     * @param workerId MSAuthCodeSigner
     * @param clientSide client side flag
     * @return the signed binary
     */
    public static File signPeAndAssertChecksum(final File sampleFile, int workerId, boolean clientSide)
            throws Exception {

        final long origChecksum;
        try (PEFile origPe = new PEFile(sampleFile)) {
            origChecksum = origPe.computeChecksum();
        }

        final File signedFile = createTempOutputFile(sampleFile);
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

            // Checksum should change
            final long newChecksum = pe.computeChecksum();
            assertNotEquals("Checksum should change", origChecksum, newChecksum);

            // New checksum should be correct (note before fix in Jsign this only works for files < 64KB)
            if (signedFile.length() >= 64 * 1024) {
                throw new Exception("For now this test case assumes a sample file less than 64KB. This can be removed when jsign is patched to support checksum calculation of larger files");
            }
            assertEquals("Correct checksum in checksum field", newChecksum, pe.getCheckSum());

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
            new CMSSignedData(new CMSProcessableByteArray(content), signatures.get(0).getEncoded());

            return signedFile;
        } finally {
            if (pe != null) {
                pe.close();
            }
        }
    }
}
