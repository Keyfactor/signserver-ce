/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.onetime.common;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.QueryCriteria;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.QueryException;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.server.cryptotokens.TokenEntry;
import org.signserver.server.cryptotokens.TokenSearchResults;
import org.signserver.testutils.ModulesTestCase;

/**
 * Test signing using a ShortLived one time crypto token.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class OneTimeP11SignTest {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(OneTimeP11SignTest.class);

    private final ModulesTestCase mt = new ModulesTestCase();
    private final WorkerSession workerSession = mt.getWorkerSession();
    private final ProcessSessionRemote processSession = mt.getProcessSession();

    private final String sharedLibraryName;
    private final String slot;
    private final String pin;
    private final String existingKey1;

    private static final String CRYPTO_TOKEN_NAME = "TestOneTimeSourceCryptoTokenP11";
    private static final String ONETIME_CRYPTO_TOKEN_NAME = "TestOneTimeCryptoTokenP11";

    private static final int CRYPTO_TOKEN = 40100;
    private static final int ONETIME_CRYPTO_TOKEN = 40200;

    private static final int GENERIC_SIGNER = 40300;
    private static final String GENERIC_DATA = "<sampledata/>";

    private final File pdfSampleFile;
    private final File odfSampleFile;
    private final File ooxmlSampleFile;
    
    protected static Random random = new Random(1234);
    private static final String USERNAME_AUTHORIZER = "org.signserver.server.UsernameAuthorizer";

    public OneTimeP11SignTest() throws FileNotFoundException {
        final File home = PathUtil.getAppHome();
        pdfSampleFile = new File(home, "res/test/pdf/sample.pdf");
        odfSampleFile = new File(home, "res/test/test.odt");
        ooxmlSampleFile = new File(home, "res/test/test.docx");

        sharedLibraryName = mt.getConfig().getProperty("test.p11.sharedLibraryName");
        slot = mt.getConfig().getProperty("test.p11.slot");
        pin = mt.getConfig().getProperty("test.p11.pin");
        existingKey1 = mt.getConfig().getProperty("test.p11.existingkey1");
    }

    @Before
    public void setUp() throws Exception {
        Assume.assumeFalse("P11NG".equalsIgnoreCase(mt.getConfig().getProperty("test.p11.provider")));
        SignServerUtil.installBCProvider();
    }

    private void setupSourceCryptoTokenProperties(final int tokenId) throws Exception {
        // Setup source crypto token
        workerSession.setWorkerProperty(tokenId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(tokenId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(tokenId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, "org.signserver.server.cryptotokens.PKCS11CryptoToken");
        workerSession.setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(tokenId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(tokenId, "SLOT", slot);
        workerSession.setWorkerProperty(tokenId, "PIN", pin);
        workerSession.setWorkerProperty(tokenId, "DEFAULTKEY", existingKey1);
    }

    private void setupOneTimeCryptoWorkerProperties(final int workerId) throws Exception {
        // Setup one time crypto worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.onetime.cryptoworker.OneTimeCryptoWorker");
        workerSession.setWorkerProperty(workerId, "NAME", ONETIME_CRYPTO_TOKEN_NAME);

        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(workerId, "KEYALG", "RSA");
        workerSession.setWorkerProperty(workerId, "KEYSPEC", "1024");
        workerSession.setWorkerProperty(workerId, "CACONNECTOR_IMPLEMENTATION", "org.signserver.module.onetime.caconnector.SelfSignedCAConnector");
        workerSession.setWorkerProperty(workerId, "CERTSIGNATUREALGORITHM", "SHA256WithRSA");
    }

    private void setupSignerPropertiesReferingToken(final int workerId, String implClass, String workerName, String authorizer) throws IOException {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, implClass);
        workerSession.setWorkerProperty(workerId, "NAME", workerName);
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", ONETIME_CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(workerId, "DISABLEKEYUSAGECOUNTER", "true"); // otherwise signing may fail       
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", authorizer);
        
        if (authorizer.equals(USERNAME_AUTHORIZER)) {
            workerSession.setWorkerProperty(workerId, "ACCEPT_ALL_USERNAMES", "true");
            workerSession.setWorkerProperty(workerId, "ALIASSELECTOR", "org.signserver.server.aliasselectors.AuthorizedUsernameAliasSelector");
        }

    }

    @Test
    public void testXAdesSigner() throws Exception {
        LOG.info("testXAdesSigner");
        try {
            setupSourceCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            setupOneTimeCryptoWorkerProperties(ONETIME_CRYPTO_TOKEN);
            workerSession.reloadConfiguration(ONETIME_CRYPTO_TOKEN);

            setupSignerPropertiesReferingToken(GENERIC_SIGNER, "org.signserver.module.xades.signer.XAdESSigner", "TestXAdESSigner", "NOAUTH");
            workerSession.reloadConfiguration(GENERIC_SIGNER);

            internalSignAndAssert(GENERIC_SIGNER, GENERIC_DATA.getBytes(), null);
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

            setupSignerPropertiesReferingToken(GENERIC_SIGNER, "org.signserver.module.cmssigner.CMSSigner", "TestCMSSigner", "NOAUTH");
            workerSession.reloadConfiguration(GENERIC_SIGNER);

            internalSignAndAssert(GENERIC_SIGNER, GENERIC_DATA.getBytes(), null);
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

            setupSignerPropertiesReferingToken(GENERIC_SIGNER, "org.signserver.module.cmssigner.PlainSigner", "TestPlainSigner", "NOAUTH");
            workerSession.reloadConfiguration(GENERIC_SIGNER);

            internalSignAndAssert(GENERIC_SIGNER, GENERIC_DATA.getBytes(), null);
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

            setupSignerPropertiesReferingToken(GENERIC_SIGNER, "org.signserver.module.xmlsigner.XMLSigner", "TestXMLSigner", "NOAUTH");
            workerSession.reloadConfiguration(GENERIC_SIGNER);

            internalSignAndAssert(GENERIC_SIGNER, GENERIC_DATA.getBytes(), null);
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

            setupSignerPropertiesReferingToken(GENERIC_SIGNER, "org.signserver.module.pdfsigner.PDFSigner", "TestPDFSigner", "NOAUTH");
            workerSession.reloadConfiguration(GENERIC_SIGNER);

            internalSignAndAssert(GENERIC_SIGNER, FileUtils.readFileToByteArray(pdfSampleFile), null);
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

            setupSignerPropertiesReferingToken(GENERIC_SIGNER, "org.signserver.module.odfsigner.ODFSigner", "TestODFSigner", "NOAUTH");
            workerSession.reloadConfiguration(GENERIC_SIGNER);

            internalSignAndAssert(GENERIC_SIGNER, FileUtils.readFileToByteArray(odfSampleFile), null);
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

            setupSignerPropertiesReferingToken(GENERIC_SIGNER, "org.signserver.module.ooxmlsigner.OOXMLSigner", "TestOOXMLSigner", "NOAUTH");
            workerSession.reloadConfiguration(GENERIC_SIGNER);

            internalSignAndAssert(GENERIC_SIGNER, FileUtils.readFileToByteArray(ooxmlSampleFile), null);
        } finally {
            mt.removeWorker(GENERIC_SIGNER);
            mt.removeWorker(ONETIME_CRYPTO_TOKEN);
            mt.removeWorker(CRYPTO_TOKEN);
        }
    }
    
    @Test
    public void testCMSSignerWithUserNameAuthorizer() throws Exception {
        LOG.info("testCMSSignerWithUserNameAuthorizer");
        try {
            setupSourceCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            setupOneTimeCryptoWorkerProperties(ONETIME_CRYPTO_TOKEN);
            workerSession.reloadConfiguration(ONETIME_CRYPTO_TOKEN);

            setupSignerPropertiesReferingToken(GENERIC_SIGNER, "org.signserver.module.cmssigner.CMSSigner", "TestCMSSigner", USERNAME_AUTHORIZER);
            workerSession.reloadConfiguration(GENERIC_SIGNER);

            for (int i = 0; i < 3; i++) {
                internalSignAndAssert(GENERIC_SIGNER, GENERIC_DATA.getBytes(), "user" + i);
            }

        } finally {
            mt.removeWorker(GENERIC_SIGNER);
            mt.removeWorker(ONETIME_CRYPTO_TOKEN);
            mt.removeWorker(CRYPTO_TOKEN);
        }
    }

    private void internalSignAndAssert(final int workerId, byte[] data, String userName) throws Exception {
        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing1
        final GenericSignResponse response1 = signGenericDocument(workerId, data, userName);        
        Certificate signercert1 = response1.getSignerCertificate();

        // Test signing2
        final GenericSignResponse response2 = signGenericDocument(workerId, data, userName);
        Certificate signercert2 = response2.getSignerCertificate();

        // Test signing3
        final GenericSignResponse response3 = signGenericDocument(workerId, data, userName);
        Certificate signercert3 = response3.getSignerCertificate();

        // check  all signer certificate and keys are different
        assertFalse("signer certificates should be different", signercert1.equals(signercert2));
        assertFalse("keys should be different", signercert1.getPublicKey().equals(signercert2.getPublicKey()));

        assertFalse("signer certificates should be different", signercert2.equals(signercert3));
        assertFalse("keys should be different", signercert2.getPublicKey().equals(signercert3.getPublicKey()));

        assertFalse("signer certificates should be different", signercert3.equals(signercert1));
        assertFalse("keys should be different", signercert3.getPublicKey().equals(signercert1.getPublicKey()));        
        
        // username should be part of SIGNER_CERT_SUBJECTDN
        if (userName != null) {
            X509Certificate x509Cert1 = (X509Certificate) signercert1;
            X509Certificate x509Cert2 = (X509Certificate) signercert2;
            X509Certificate x509Cert3 = (X509Certificate) signercert3;
            assertTrue("SIGNER_CERT_SUBJECTDN should contain user name", x509Cert1.getSubjectDN().toString().contains(userName));
            assertTrue("SIGNER_CERT_SUBJECTDN should contain user name", x509Cert2.getSubjectDN().toString().contains(userName));
            assertTrue("SIGNER_CERT_SUBJECTDN should contain user name", x509Cert3.getSubjectDN().toString().contains(userName));
        }

        // Only one key (existingKey1) should be present in crypto token as short-lived-one-time key should have been deleted
        TokenSearchResults searchResults = searchTokenEntries(0, Integer.MAX_VALUE, QueryCriteria.create(), false);
        List<TokenEntry> entries = searchResults.getEntries();
        assertEquals("Only one key " + existingKey1 + " should exist in crypto token but keys "
                + entries.toString() + " exist", 1, entries.size());

    }    
    
    private TokenSearchResults searchTokenEntries(int startIndex, int max, QueryCriteria qc, boolean includeData) throws OperationUnsupportedException, CryptoTokenOfflineException, QueryException, InvalidWorkerIdException, SignServerException, AuthorizationDeniedException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
        return mt.getWorkerSession().searchTokenEntries(new WorkerIdentifier(CRYPTO_TOKEN), startIndex, max, qc, includeData, Collections.<String, Object>emptyMap());
    }
    
    /**
     * Make a GenericSignRequest.
     */
    private GenericSignResponse signGenericDocument(final int workerId, final byte[] data, String userName) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        final int requestId = random.nextInt();
        final GenericSignRequest request = new GenericSignRequest(requestId, data);

        RemoteRequestContext remoteRequestContext = new RemoteRequestContext();
        if (userName != null) {
            remoteRequestContext.setUsername(userName);
            remoteRequestContext.setPassword("");
        }
        final GenericSignResponse response = (GenericSignResponse) processSession.process(new WorkerIdentifier(workerId), request, remoteRequestContext);
        assertEquals("requestId", requestId, response.getRequestID());
        Certificate signercert = response.getSignerCertificate();
        assertNotNull(signercert);
        return response;
    }

}
