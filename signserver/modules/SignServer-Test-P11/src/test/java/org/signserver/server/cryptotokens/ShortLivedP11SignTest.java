/** ***********************************************************************
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
package org.signserver.server.cryptotokens;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.Certificate;
import java.util.List;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertFalse;
import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.testutils.ModulesTestCase;

/**
 * Test signing using a ShortLived one time crypto token.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class ShortLivedP11SignTest {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(ShortLivedP11SignTest.class);

    private final ModulesTestCase mt = new ModulesTestCase();
    private final WorkerSession workerSession = mt.getWorkerSession();
    private final ProcessSessionRemote processSession = mt.getProcessSession();

    private final String sharedLibraryName;
    private final String sharedLibraryPath;
    private final String slot;
    private final String pin;
    private final String existingKey1;

    private static final String CRYPTO_TOKEN_NAME = "TestShortLivedSourceCryptoTokenP11";
    private static final String ONETIME_CRYPTO_TOKEN_NAME = "TestShortLivedOneTimeCryptoTokenP11";

    private static final int CRYPTO_TOKEN = 40100;
    private static final int ONETIME_CRYPTO_TOKEN = 40200;

    private static final int GENERIC_SIGNER = 40300;
    private static final String GENERIC_DATA = "<sampledata/>";
    
    private final File pdfSampleFile;
    private final File odfSampleFile;
    private final File ooxmlSampleFile;

    public ShortLivedP11SignTest() throws FileNotFoundException {
        final File home = PathUtil.getAppHome();
        pdfSampleFile = new File(home, "res/test/pdf/sample.pdf");
        odfSampleFile = new File(home, "res/test/test.odt");
        ooxmlSampleFile = new File(home, "res/test/test.docx");
        
        sharedLibraryName = mt.getConfig().getProperty("test.p11.sharedLibraryName");
        sharedLibraryPath = mt.getConfig().getProperty("test.p11.sharedLibraryPath");
        slot = mt.getConfig().getProperty("test.p11.slot");
        pin = mt.getConfig().getProperty("test.p11.pin");
        existingKey1 = mt.getConfig().getProperty("test.p11.existingkey1");
    }

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    private void setupSourceCryptoTokenProperties(final int tokenId) throws Exception {
        // Setup source crypto token
        workerSession.setWorkerProperty(tokenId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(tokenId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(tokenId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(tokenId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(tokenId, "SLOT", slot);
        workerSession.setWorkerProperty(tokenId, "PIN", pin);
        workerSession.setWorkerProperty(tokenId, "DEFAULTKEY", existingKey1);
    }

    private void setupOneTimeCryptoWorkerProperties(final int workerId) throws Exception {
        // Setup one time crypto worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.enterprise.caconnector.OneTimeCryptoWorker");
        workerSession.setWorkerProperty(workerId, "NAME", ONETIME_CRYPTO_TOKEN_NAME);

        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(workerId, "KEYALG", "RSA");
        workerSession.setWorkerProperty(workerId, "KEYSPEC", "1024");
        workerSession.setWorkerProperty(workerId, "CACONNECTOR_IMPLEMENTATION", "org.signserver.server.enterprise.caconnector.SelfSignedCAConnector");
        workerSession.setWorkerProperty(workerId, "CERTSIGNATUREALGORITHM", "SHA256WithRSA");
    }

    private void setupSignerPropertiesReferingToken(final int workerId, String implClass, String workerName) throws IOException {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, implClass);
        workerSession.setWorkerProperty(workerId, "NAME", workerName);
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", ONETIME_CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(workerId, "DISABLEKEYUSAGECOUNTER", "true"); // otherwise signing may fail
    }

    @Test
    public void testXAdesSigner() throws Exception {
        LOG.info("testXAdesSigner");
        try {
            setupSourceCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            setupOneTimeCryptoWorkerProperties(ONETIME_CRYPTO_TOKEN);
            workerSession.reloadConfiguration(ONETIME_CRYPTO_TOKEN);

            setupSignerPropertiesReferingToken(GENERIC_SIGNER, "org.signserver.module.xades.signer.XAdESSigner", "TestXAdESSigner");
            workerSession.reloadConfiguration(GENERIC_SIGNER);

            internalSignAndAssert(GENERIC_SIGNER, GENERIC_DATA.getBytes());
        } finally {
            mt.removeWorker(GENERIC_SIGNER);
            mt.removeWorker(ONETIME_CRYPTO_TOKEN);
            mt.removeWorker(CRYPTO_TOKEN);
        }
    }
    
    @Test
    public void testCMSSigner() throws Exception {
        LOG.info("testCMSSigner");
        try {
            setupSourceCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            setupOneTimeCryptoWorkerProperties(ONETIME_CRYPTO_TOKEN);
            workerSession.reloadConfiguration(ONETIME_CRYPTO_TOKEN);

            setupSignerPropertiesReferingToken(GENERIC_SIGNER, "org.signserver.module.cmssigner.CMSSigner", "TestCMSSigner");
            workerSession.reloadConfiguration(GENERIC_SIGNER);

            internalSignAndAssert(GENERIC_SIGNER, GENERIC_DATA.getBytes());
        } finally {
            mt.removeWorker(GENERIC_SIGNER);
            mt.removeWorker(ONETIME_CRYPTO_TOKEN);
            mt.removeWorker(CRYPTO_TOKEN);
        }
    }
    
    @Test
    public void testPlainSigner() throws Exception {
        LOG.info("testPlainSigner");
        try {
            setupSourceCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            setupOneTimeCryptoWorkerProperties(ONETIME_CRYPTO_TOKEN);
            workerSession.reloadConfiguration(ONETIME_CRYPTO_TOKEN);

            setupSignerPropertiesReferingToken(GENERIC_SIGNER, "org.signserver.module.cmssigner.PlainSigner", "TestPlainSigner");
            workerSession.reloadConfiguration(GENERIC_SIGNER);

            internalSignAndAssert(GENERIC_SIGNER, GENERIC_DATA.getBytes());
        } finally {
            mt.removeWorker(GENERIC_SIGNER);
            mt.removeWorker(ONETIME_CRYPTO_TOKEN);
            mt.removeWorker(CRYPTO_TOKEN);
        }
    }
    
    @Test
    public void testXMLSigner() throws Exception {
        LOG.info("testXMLSigner");
        try {
            setupSourceCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            setupOneTimeCryptoWorkerProperties(ONETIME_CRYPTO_TOKEN);
            workerSession.reloadConfiguration(ONETIME_CRYPTO_TOKEN);

            setupSignerPropertiesReferingToken(GENERIC_SIGNER, "org.signserver.module.xmlsigner.XMLSigner", "TestXMLSigner");
            workerSession.reloadConfiguration(GENERIC_SIGNER);

            internalSignAndAssert(GENERIC_SIGNER, GENERIC_DATA.getBytes());
        } finally {
            mt.removeWorker(GENERIC_SIGNER);
            mt.removeWorker(ONETIME_CRYPTO_TOKEN);
            mt.removeWorker(CRYPTO_TOKEN);
        }
    }
    
    @Test
    public void testPDFSigner() throws Exception {
        LOG.info("testPDFSigner");
        try {
            setupSourceCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            setupOneTimeCryptoWorkerProperties(ONETIME_CRYPTO_TOKEN);
            workerSession.reloadConfiguration(ONETIME_CRYPTO_TOKEN);

            setupSignerPropertiesReferingToken(GENERIC_SIGNER, "org.signserver.module.pdfsigner.PDFSigner", "TestPDFSigner");
            workerSession.reloadConfiguration(GENERIC_SIGNER);

            internalSignAndAssert(GENERIC_SIGNER, readFile(pdfSampleFile));
        } finally {
            mt.removeWorker(GENERIC_SIGNER);
            mt.removeWorker(ONETIME_CRYPTO_TOKEN);
            mt.removeWorker(CRYPTO_TOKEN);
        }
    }
    
    @Test
    public void testODFSigner() throws Exception {
        LOG.info("testODFSigner");
        try {
            setupSourceCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            setupOneTimeCryptoWorkerProperties(ONETIME_CRYPTO_TOKEN);
            workerSession.reloadConfiguration(ONETIME_CRYPTO_TOKEN);

            setupSignerPropertiesReferingToken(GENERIC_SIGNER, "org.signserver.module.odfsigner.ODFSigner", "TestODFSigner");
            workerSession.reloadConfiguration(GENERIC_SIGNER);

            internalSignAndAssert(GENERIC_SIGNER, readFile(odfSampleFile));
        } finally {
            mt.removeWorker(GENERIC_SIGNER);
            mt.removeWorker(ONETIME_CRYPTO_TOKEN);
            mt.removeWorker(CRYPTO_TOKEN);
        }
    }
    
    @Test
    public void testOOXMLSigner() throws Exception {
        LOG.info("testOOXMLSigner");
        try {
            setupSourceCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            setupOneTimeCryptoWorkerProperties(ONETIME_CRYPTO_TOKEN);
            workerSession.reloadConfiguration(ONETIME_CRYPTO_TOKEN);

            setupSignerPropertiesReferingToken(GENERIC_SIGNER, "org.signserver.module.ooxmlsigner.OOXMLSigner", "TestOOXMLSigner");
            workerSession.reloadConfiguration(GENERIC_SIGNER);

            internalSignAndAssert(GENERIC_SIGNER, readFile(ooxmlSampleFile));
        } finally {
            mt.removeWorker(GENERIC_SIGNER);
            mt.removeWorker(ONETIME_CRYPTO_TOKEN);
            mt.removeWorker(CRYPTO_TOKEN);
        }
    }

    private void internalSignAndAssert(final int workerId, byte[] data) throws Exception {
        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing1
        final GenericSignResponse response1 = mt.signGenericDocument(workerId, data);
        Certificate signercert1 = response1.getSignerCertificate();

        // Test signing2
        final GenericSignResponse response2 = mt.signGenericDocument(workerId, data);
        Certificate signercert2 = response2.getSignerCertificate();

        // Test signing3
        final GenericSignResponse response3 = mt.signGenericDocument(workerId, data);
        Certificate signercert3 = response3.getSignerCertificate();

        // check  all signer certificate and keys are different
        assertFalse("signer certificates should be different", signercert1.equals(signercert2));
        assertFalse("keys should be different", signercert1.getPublicKey().equals(signercert2.getPublicKey()));

        assertFalse("signer certificates should be different", signercert2.equals(signercert3));
        assertFalse("keys should be different", signercert2.getPublicKey().equals(signercert3.getPublicKey()));

        assertFalse("signer certificates should be different", signercert3.equals(signercert1));
        assertFalse("keys should be different", signercert3.getPublicKey().equals(signercert1.getPublicKey()));

    }
    
    private byte[] readFile(File file) throws IOException {
        BufferedInputStream in = new BufferedInputStream(new FileInputStream(
                file));
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            bout.write(b);
        }
        return bout.toByteArray();
    }

}
