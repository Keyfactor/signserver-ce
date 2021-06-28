/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.ades.signer;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import static junit.framework.TestCase.fail;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.module.extendedcmssigner.ExtendedCMSSigner;
import org.signserver.server.FixedTimeSource;
import org.signserver.testutils.ModulesTestCase;

/**
 * System tests for AdESSigner.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public abstract class AbstractAdESSignerTestBase extends ModulesTestCase {

    private static final Logger LOG = Logger.getLogger(AbstractAdESSignerTestBase.class);

    private File samplePdf;
    private File sampleXml;
    private File trustStore;

    protected final static int WORKER_ID = 9000;
    protected final static String WORKER_NAME = "TestAdESSigner";
    private final static int CRYPTO_TOKEN_ID = 9001;
    private final static String CRYPTO_TOKEN_NAME = "TestCryptoWorker";
    private final static int TSA_WORKER_ID = 9002;
    private final static String TSA_WORKER_NAME = "TestAdESTimeStampSigner";

    private final WorkerSessionRemote workerSession = getWorkerSession();
    private final ProcessSessionRemote processSession = getProcessSession();

    @Before
    public void setUp() throws Exception {
        LOG.debug(">setUp");
        samplePdf = new File(PathUtil.getAppHome(), "res/test/pdf/sample.pdf");
        if (!samplePdf.exists()) {
            throw new Exception("Missing sample PDF: " + samplePdf);
        }
        sampleXml = new File(PathUtil.getAppHome(), "res/test/sample.xml");
        if (!sampleXml.exists()) {
            throw new Exception("Missing sample XML: " + sampleXml);
        }
        setupCryptoToken(CRYPTO_TOKEN_ID, CRYPTO_TOKEN_NAME);
        workerSession.reloadConfiguration(CRYPTO_TOKEN_ID);

        // Redefine the XML factories to use the ones with the JRE instead of
        // it being the first on the classpath as for instance the Xerces in
        // JBoss does not work with the default way DSS creates secure factories
        LOG.info("Previous transformer property: " + System.getProperty("javax.xml.transform.TransformerFactory"));
        System.setProperty("javax.xml.transform.TransformerFactory", "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl");
        LOG.info("Current  transformer property: " + System.getProperty("javax.xml.transform.TransformerFactory"));
        LOG.info("Previous schema property:      " + System.getProperty("javax.xml.validation.SchemaFactory:http://www.w3.org/2001/XMLSchema"));
        System.setProperty("javax.xml.validation.SchemaFactory:http://www.w3.org/2001/XMLSchema", "com.sun.org.apache.xerces.internal.jaxp.validation.XMLSchemaFactory");
        LOG.info("Current  schema property:      " + System.getProperty("javax.xml.validation.SchemaFactory:http://www.w3.org/2001/XMLSchema"));
        
        trustStore = new File(PathUtil.getAppHome(), "res/test/dss10/dss10_truststore.jks");
        if (!trustStore.exists()) {
            throw new Exception("Missing truststore: " + trustStore);
        }
    }

    @After
    public void cleanUp() {
        LOG.debug(">cleanUp");
        removeWorker(WORKER_ID);
        removeWorker(CRYPTO_TOKEN_ID);
    }
    
    /**
     * Setup a crypto token with the supplied ID and name.
     *
     * @param cryptoTokenId id to use
     * @param cryptoTokenName name to use
     * @throws java.lang.Exception
     */
    protected abstract void setupCryptoToken(int cryptoTokenId, String cryptoTokenName) throws Exception;
    
    /**
     * @return The key alias of an existing key to use
     */
    protected abstract String getDefaultKey();

    protected void assertSignedOKPdf(final DigestAlgorithm expectedDigAlg, final SignatureAlgorithm expectedSigAlg, final String expectedSigAlgOid, Date expectedSignatureTimeStamp, String expectedSignatureTimeStampDigestOid, Date expectedContentTimeStamp, String expectedContentTimeStampDigestOid)
            throws Exception {
        final RemoteRequestContext requestContext = new RemoteRequestContext();
        final byte[] sampleFile = FileUtils.readFileToByteArray(samplePdf);
        final GenericSignRequest request = new GenericSignRequest(100, sampleFile);
        final GenericSignResponse response =
                (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_ID),
                                                             request,
                                                             requestContext);

        final byte[] signedData = response.getProcessedData();
        final DSSDocument document = new InMemoryDocument(signedData);
        final PDFDocumentValidator documentValidator =
                new PDFDocumentValidator(document);

        final List<AdvancedSignature> signatures =
                documentValidator.getSignatures();

        assertEquals("Number of signatures", 1, signatures.size());

        final AdvancedSignature sig = signatures.get(0);

        assertEquals("Digest algorithm", expectedDigAlg,
                     sig.getDigestAlgorithm());
        assertEquals("Signature algorithm", expectedSigAlg,
                     sig.getSignatureAlgorithm());
        
        sig.checkSignatureIntegrity();
        
        PAdESSignature pades = (PAdESSignature) sig;
        
        byte[] originalData = pades.getPdfRevision().getRevisionCoveredBytes();
        
        CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(originalData), pades.getCmsSignedData().getEncoded());
        
        assertVerifiedCms(cms, expectedSigAlg, expectedSigAlgOid, expectedSignatureTimeStamp, expectedSignatureTimeStampDigestOid, expectedContentTimeStamp, expectedContentTimeStampDigestOid);
        
        // Document validation using DSS
        validate(document);
    }

    protected void assertSignedOKXml(final DigestAlgorithm expectedDigAlg, final SignatureAlgorithm expectedSigAlg, final String expectedSigAlgOid, Date expectedSignatureTimeStamp, String expectedSignatureTimeStampDigestOid, Date expectedContentTimeStamp, String expectedContentTimeStampDigestOid)
            throws Exception {
        final RemoteRequestContext requestContext = new RemoteRequestContext();
        final byte[] sampleFile = FileUtils.readFileToByteArray(sampleXml);
        final GenericSignRequest request = new GenericSignRequest(100, sampleFile);
        final GenericSignResponse response =
                (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_ID),
                                                             request,
                                                             requestContext);

        final byte[] signedData = response.getProcessedData();
        final DSSDocument document = new InMemoryDocument(signedData);
        final XMLDocumentValidator documentValidator =
                new XMLDocumentValidator(document);

        final List<AdvancedSignature> signatures =
                documentValidator.getSignatures();

        assertEquals("Number of signatures", 1, signatures.size());

        final AdvancedSignature sig = signatures.get(0);

        assertEquals("Digest algorithm", expectedDigAlg,
                     sig.getDigestAlgorithm());
        assertEquals("Signature algorithm", expectedSigAlg,
                     sig.getSignatureAlgorithm());
        
        sig.checkSignatureIntegrity();

        // Document validation using DSS
        validate(document);
    }
    
    protected void assertSignedNotOk() throws Exception {
        final RemoteRequestContext requestContext = new RemoteRequestContext();
        final byte[] sampleFile = FileUtils.readFileToByteArray(samplePdf);
        final GenericSignRequest request = new GenericSignRequest(100, sampleFile);
        processSession.process(new WorkerIdentifier(WORKER_ID), request, requestContext);
        fail("Should have failed");
    }
    
    private void assertVerifiedCms(CMSSignedData signedData, final SignatureAlgorithm expectedSigAlg, String expectedSigOid, Date expectedTimeStamp, String expectedSignatureTimeStampDigestOid, Date expectedContentTimeStamp, String expectedContentTimeStampDigestOid) throws OperatorCreationException, CertificateException, CMSException, IOException, TSPException, NoSuchAlgorithmException {
        
        //String expectedSigOid = expectedSigAlg.getOid();
        
        int verified = 0;
            
        Store                   certStore = signedData.getCertificates();
        SignerInformationStore  signers = signedData.getSignerInfos();
        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext()) {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(signer.getSID());

            Iterator              certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals("expected signature " + expectedSigAlg, signer.getEncryptionAlgOID(), expectedSigOid);       
            
            if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
                verified++;
                
                // Check signature time-stamp token
                if (expectedSignatureTimeStampDigestOid != null) {
                    final Attribute tsAttr = signer.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
                    assertNotNull("Unsigned attribute present", tsAttr);

                    final TimeStampToken tst = new TimeStampToken(new CMSSignedData(tsAttr.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
                    assertEquals("TST digest alg oid", expectedSignatureTimeStampDigestOid, tst.getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId());

                    assertEquals("Timestamp time equals", expectedTimeStamp, tst.getTimeStampInfo().getGenTime());
                    
                    // Check that message imprint is digest of the signature value
                    byte[] expectedDigest = DigestAlgorithm.forOID(expectedSignatureTimeStampDigestOid).getMessageDigest().digest(signer.getSignature());
                    assertEquals("TST message imprint value", Hex.toHexString(expectedDigest), Hex.toHexString(tst.getTimeStampInfo().getMessageImprintDigest()));
                }

                // Check content time-stamp token
                if (expectedContentTimeStampDigestOid != null) {
                    final Attribute tsAttr = signer.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_contentTimestamp);
                    assertNotNull("Signed attribute present", tsAttr);

                    final TimeStampToken tst = new TimeStampToken(new CMSSignedData(tsAttr.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
                    assertEquals("TST digest alg oid", expectedContentTimeStampDigestOid, tst.getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId());

                    assertEquals("Timestamp time equals", expectedContentTimeStamp, tst.getTimeStampInfo().getGenTime());
                    
                    // Check that message imprint is digest of the content value
                    final Attribute mdAttr = signer.getSignedAttributes().get(CMSAttributes.messageDigest);
                    final ASN1OctetString messageDigestObject = ASN1OctetString.getInstance(mdAttr.getAttrValues().getObjectAt(0).toASN1Primitive());

                    byte[] expectedDigest = messageDigestObject.getOctets();

                    assertEquals("TST message imprint value", Hex.toHexString(expectedDigest), Hex.toHexString(tst.getTimeStampInfo().getMessageImprintDigest()));
                }
            }   
        }

        assertTrue("verified", verified > 0);
    }
    

    protected void setupBasicSignerProperties(final int workerId,
                                              final String digestAlgorithm,
                                              final String signatureAlgorithm,
                                              final String signatureFormat) {
        LOG.debug(">setSigner");
        // Setup worker
        workerSession.setWorkerProperty(workerId,
                                        WorkerConfig.IMPLEMENTATION_CLASS,
                                        "org.signserver.module.ades.signer.AdESSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE,
                                        WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, "NAME", WORKER_NAME);
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN",
                                        CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", getDefaultKey());
        workerSession.setWorkerProperty(workerId, "SIGNATURE_FORMAT",
                                        signatureFormat);
        workerSession.setWorkerProperty(workerId, "SIGNATURE_LEVEL",
                                        "BASELINE-B");

        if ("XAdES".equals(signatureFormat)) {
            // always test with enveloped packaging for XAdES, we should have unit
            // tests for the packaging formats
            workerSession.setWorkerProperty(workerId, "SIGNATURE_PACKAGING",
                                            "ENVELOPED");
        }
        
        if (digestAlgorithm != null) {
            workerSession.setWorkerProperty(workerId, "DIGESTALGORITHM", digestAlgorithm);
        } else {
            workerSession.removeWorkerProperty(workerId, "DIGESTALGORITHM");
        }
        if (signatureAlgorithm != null) {
            workerSession.setWorkerProperty(workerId, "SIGNATUREALGORITHM", signatureAlgorithm);
        } else {
            workerSession.removeWorkerProperty(workerId, "SIGNATUREALGORITHM");
        }
    }

    /**
     * Tests signing using default algorithms.
     * @throws java.lang.Exception
     */
    @Test
    public void testBasicSigning() throws Exception {
        LOG.info("testBasicSigning");
        setupBasicSignerProperties(WORKER_ID, null, null, "PAdES");
        workerSession.reloadConfiguration(WORKER_ID);
        assertSignedOKPdf(DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), null, null, null, null);
    }

    /**
     * Tests signing using default algorithms.
     * @throws java.lang.Exception
     */
    @Test
    public void testBasicSigningXAdES() throws Exception {
        LOG.info("testBasicSigningXAdES");
        setupBasicSignerProperties(WORKER_ID, null, null, "XAdES");
        workerSession.reloadConfiguration(WORKER_ID);
        assertSignedOKXml(DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), null, null, null, null);
    }
    
    /**
     * Tests using specified digest algorithm.
     * @throws java.lang.Exception
     */
    @Test
    public void testBasicSigning_SHA256() throws Exception {
        LOG.info("testBasicSigning_SHA256");
        setupBasicSignerProperties(WORKER_ID, "SHA256", null, "PAdES");
        workerSession.reloadConfiguration(WORKER_ID);
        assertSignedOKPdf(DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), null, null, null, null);
    }

    /**
     * Tests using specified digest algorithm.
     * @throws java.lang.Exception
     */
    @Test
    public void testBasicSigningXAdES_SHA256() throws Exception {
        LOG.info("testBasicSigningXAdES_SHA256");
        setupBasicSignerProperties(WORKER_ID, "SHA256", null, "XAdES");
        workerSession.reloadConfiguration(WORKER_ID);
        assertSignedOKXml(DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), null, null, null, null);
    }

    /**
     * Tests using specified digest algorithm.
     * @throws java.lang.Exception
     */
    @Test
    public void testBasicSigning_SHA384() throws Exception {
        LOG.info("testBasicSigning_SHA384");
        setupBasicSignerProperties(WORKER_ID, "SHA384", null, "PAdES");
        workerSession.reloadConfiguration(WORKER_ID);
        assertSignedOKPdf(DigestAlgorithm.SHA384, SignatureAlgorithm.RSA_SHA384, PKCSObjectIdentifiers.sha384WithRSAEncryption.getId(), null, null, null, null);
    }
    
    /**
     * Tests using specified digest algorithm. 
     * @throws java.lang.Exception
     */
    @Test
    public void testBasicSigning_SHA512() throws Exception {
        LOG.info("testBasicSigning_SHA512");
        setupBasicSignerProperties(WORKER_ID, "SHA512", null, "PAdES");
        workerSession.reloadConfiguration(WORKER_ID);
        assertSignedOKPdf(DigestAlgorithm.SHA512, SignatureAlgorithm.RSA_SHA512, PKCSObjectIdentifiers.sha512WithRSAEncryption.getId(), null, null, null, null);
    }
    
    /**
     * Tests using specified signature algorithm. 
     * @throws java.lang.Exception
     */
    @Test
    public void testBasicSigning_SHA256withRSA() throws Exception {
        LOG.info("testBasicSigning_SHA256withRSA");
        setupBasicSignerProperties(WORKER_ID, null, "SHA256withRSA", "PAdES");
        workerSession.reloadConfiguration(WORKER_ID);
        assertSignedOKPdf(DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), null, null, null, null);
    }
    
    /**
     * Tests using specified signature algorithm. 
     * @throws java.lang.Exception
     */
    @Test
    public void testBasicSigning_SHA384withRSA() throws Exception {
        LOG.info("testBasicSigning_SHA384withRSA");
        setupBasicSignerProperties(WORKER_ID, null, "SHA384withRSA", "PAdES");
        workerSession.reloadConfiguration(WORKER_ID);
        assertSignedOKPdf(DigestAlgorithm.SHA384, SignatureAlgorithm.RSA_SHA384, PKCSObjectIdentifiers.sha384WithRSAEncryption.getId(), null, null, null, null);
    }

    /**
     * Tests using specified signature algorithm. 
     * @throws java.lang.Exception
     */
    @Test
    public void testBasicSigning_SHA512withRSA() throws Exception {
        LOG.info("testBasicSigning_SHA512withRSA");
        setupBasicSignerProperties(WORKER_ID, null, "SHA512withRSA", "PAdES");
        workerSession.reloadConfiguration(WORKER_ID);
        assertSignedOKPdf(DigestAlgorithm.SHA512, SignatureAlgorithm.RSA_SHA512, PKCSObjectIdentifiers.sha512WithRSAEncryption.getId(), null, null, null, null);
    }
    
    /**
     * Tests using specified PSS signature algorithm. 
     * @throws java.lang.Exception
     */
    @Test
    public void testBasicSigning_SHA256withRSAandMGF1() throws Exception {
        LOG.info("testBasicSigning_SHA256withRSAandMGF1");
        setupBasicSignerProperties(WORKER_ID, null, "SHA256withRSAandMGF1",
                                   "PAdES");
        workerSession.reloadConfiguration(WORKER_ID);
        assertSignedOKPdf(DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1, "1.2.840.113549.1.1.10", null, null, null, null);
    }

    /**
     * Tests using specified PSS signature algorithm. 
     * @throws java.lang.Exception
     */
    @Test
    public void testBasicSigning_SHA384withRSAandMGF1() throws Exception {
        LOG.info("testBasicSigning_SHA384withRSAandMGF1");
        setupBasicSignerProperties(WORKER_ID, null, "SHA384withRSAandMGF1",
                                   "PAdES");
        workerSession.reloadConfiguration(WORKER_ID);
        assertSignedOKPdf(DigestAlgorithm.SHA384, SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1, "1.2.840.113549.1.1.10", null, null, null, null);
    }

    /**
     * Tests using specified PSS signature algorithm. 
     * @throws java.lang.Exception
     */
    @Test
    public void testBasicSigning_SHA512withRSAandMGF1() throws Exception {
        LOG.info("testBasicSigning_SHA512withRSAandMGF1");
        setupBasicSignerProperties(WORKER_ID, null, "SHA512withRSAandMGF1",
                                   "PAdES");
        workerSession.reloadConfiguration(WORKER_ID);
        assertSignedOKPdf(DigestAlgorithm.SHA512, SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, "1.2.840.113549.1.1.10", null, null, null, null);
    }
    
    private void setupTimeStampSigner(int workerId, String workerName, Date time, String username, String password) throws FileNotFoundException {
        addTimeStampSigner(workerId, workerName, true);
        addSigner(ExtendedCMSSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
        if (time != null) {
            workerSession.setWorkerProperty(workerId, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(workerId, "FIXEDTIME", String.valueOf(time.getTime()));
        }
        if (username != null) {
            workerSession.setWorkerProperty(workerId, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
            workerSession.setWorkerProperty(workerId, "USER.USER1", password);
        }
        workerSession.reloadConfiguration(workerId);
    }
    
    protected boolean validate(DSSDocument document) throws IOException {        
        // First, we need a Certificate verifier
        CertificateVerifier cv = new CommonCertificateVerifier();

        // We can inject several sources. eg: OCSP, CRL, AIA, trusted lists

        // Capability to download resources from AIA
        cv.setDataLoader(new CommonsDataLoader());

        // Capability to request OCSP Responders
        cv.setOcspSource(new OnlineOCSPSource());

        // Capability to download CRL
        cv.setCrlSource(new OnlineCRLSource());

        // Create an instance of a trusted certificate source
        CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
        // import the keystore as trusted
        trustedCertSource.importAsTrusted(new KeyStoreCertificateSource(trustStore, "JKS", "changeit"));

        // Add trust anchors (trusted list, keystore,...) to a list of trusted certificate sources
        // Hint : use method {@code CertificateVerifier.setTrustedCertSources(certSources)} in order to overwrite the existing list
        cv.addTrustedCertSources(trustedCertSource);

        // Additionally add missing certificates to a list of adjunct certificate sources
        //cv.addAdjunctCertSources(adjunctCertSource);

        // Here is the document to be validated (any kind of signature file)
        //DSSDocument document = new FileDocument(new File("src/test/resources/signature-pool/signedXmlXadesLT.xml"));

        // We create an instance of DocumentValidator
        // It will automatically select the supported validator from the classpath
        SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(document);

        // We add the certificate verifier (which allows to verify and trust certificates)
        documentValidator.setCertificateVerifier(cv);

        // Here, everything is ready. We can execute the validation (for the example, we use the default and embedded
        // validation policy)
        Reports reports = documentValidator.validateDocument();

        // We have 3 reports
        // The diagnostic data which contains all used and static data
        //DiagnosticData diagnosticData = reports.getDiagnosticData();

        // The detailed report which is the result of the process of the diagnostic data and the validation policy
        //DetailedReport detailedReport = reports.getDetailedReport();

        // The simple report is a summary of the detailed report (more user-friendly)
        SimpleReport simpleReport = reports.getSimpleReport();
        
        return simpleReport.isValid(simpleReport.getFirstSignatureId()); // XXX we only look at first here
    }
        
    /**
     * Tests signing using default algorithms at level T with internal TSA.
     * @throws Exception in case of test error
     */
    @Test
    public void testBaselineTSigning_internalTSA() throws Exception {
        LOG.info("testBaselineTSigning_internalTSA");
        try {
            final Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            setupTimeStampSigner(TSA_WORKER_ID, TSA_WORKER_NAME, time, null, null);
            setupBasicSignerProperties(WORKER_ID, null, null, "PAdES");
            workerSession.setWorkerProperty(WORKER_ID, "SIGNATURE_LEVEL", "BASELINE-T");
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TSA_WORKER_NAME);
            workerSession.reloadConfiguration(WORKER_ID);
            assertSignedOKPdf(DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), time, DigestAlgorithm.SHA256.getOid(), null, null);
        } finally {
            removeWorker(TSA_WORKER_ID);
        }
    }

    /**
     * Tests signing using default algorithms at level T with internal TSA.
     * @throws Exception in case of test error
     */
    @Test
    public void testBaselineTSigningXAdES_internalTSA() throws Exception {
        LOG.info("testBaselineTSigningXAdES_internalTSA");
        try {
            final Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            setupTimeStampSigner(TSA_WORKER_ID, TSA_WORKER_NAME, time, null, null);
            setupBasicSignerProperties(WORKER_ID, null, null, "XAdES");
            workerSession.setWorkerProperty(WORKER_ID, "SIGNATURE_LEVEL", "BASELINE-T");
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TSA_WORKER_NAME);
            workerSession.reloadConfiguration(WORKER_ID);
            assertSignedOKXml(DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), time, DigestAlgorithm.SHA256.getOid(), null, null);
        } finally {
            removeWorker(TSA_WORKER_ID);
        }
    }

    
    /**
     * Tests signing using default algorithms at level T with internal TSA.
     * @throws Exception in case of test error
     */
    @Test
    public void testBaselineTSigning_externalTSA() throws Exception {
        LOG.info("testBaselineTSigning_externalTSA");
        try {
            final Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            setupTimeStampSigner(TSA_WORKER_ID, TSA_WORKER_NAME, time, null, null);
            setupBasicSignerProperties(WORKER_ID, null, null, "PAdES");
            workerSession.setWorkerProperty(WORKER_ID, "SIGNATURE_LEVEL", "BASELINE-T");
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerName=" + TSA_WORKER_NAME);
            workerSession.reloadConfiguration(WORKER_ID);
            assertSignedOKPdf(DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), time, DigestAlgorithm.SHA256.getOid(), null, null);
        } finally {
            removeWorker(TSA_WORKER_ID);
        }
    }

    /**
     * Tests signing using default algorithms at level T with internal TSA.
     * @throws Exception in case of test error
     */
    @Test
    public void testBaselineTSigningXAdES_externalTSA() throws Exception {
        LOG.info("testBaselineTSigningXAdES_externalTSA");
        try {
            final Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            setupTimeStampSigner(TSA_WORKER_ID, TSA_WORKER_NAME, time, null, null);
            setupBasicSignerProperties(WORKER_ID, null, null, "XAdES");
            workerSession.setWorkerProperty(WORKER_ID, "SIGNATURE_LEVEL", "BASELINE-T");
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerName=" + TSA_WORKER_NAME);
            workerSession.reloadConfiguration(WORKER_ID);
            assertSignedOKXml(DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), time, DigestAlgorithm.SHA256.getOid(), null, null);
        } finally {
            removeWorker(TSA_WORKER_ID);
        }
    }
    
    /**
     * Tests signing using default algorithms at level T with internal TSA and 
     * using SHA-512 as time-stamp digest.
     * @throws Exception in case of test error
     */
    @Test
    public void testBaselineTSigning_internalTSA_SHA512() throws Exception {
        LOG.info("testBaselineTSigning_internalTSA_SHA512");
        try {
            final Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            setupTimeStampSigner(TSA_WORKER_ID, TSA_WORKER_NAME, time, null, null);
            setupBasicSignerProperties(WORKER_ID, null, null, "PAdES");
            workerSession.setWorkerProperty(WORKER_ID, "SIGNATURE_LEVEL", "BASELINE-T");
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TSA_WORKER_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_DIGESTALGORITHM", "SHA512");
            workerSession.reloadConfiguration(WORKER_ID);
            assertSignedOKPdf(DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), time, DigestAlgorithm.SHA512.getOid(), null, null);
        } finally {
            removeWorker(TSA_WORKER_ID);
        }
    }

    /**
     * Tests signing using default algorithms at level T with external TSA and 
     * using SHA-512 as time-stamp digest.
     * @throws Exception in case of test error
     */
    @Test
    public void testBaselineTSigning_externalTSA_SHA512() throws Exception {
        LOG.info("testBaselineTSigning_externalTSA_SHA512");
        try {
            final Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            setupTimeStampSigner(TSA_WORKER_ID, TSA_WORKER_NAME, time, null, null);
            setupBasicSignerProperties(WORKER_ID, null, null, "PAdES");
            workerSession.setWorkerProperty(WORKER_ID, "SIGNATURE_LEVEL", "BASELINE-T");
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerName=" + TSA_WORKER_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_DIGESTALGORITHM", "SHA512");
            workerSession.reloadConfiguration(WORKER_ID);
            assertSignedOKPdf(DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), time, DigestAlgorithm.SHA512.getOid(), null, null);
        } finally {
            removeWorker(TSA_WORKER_ID);
        }
    }
    
    /**
     * Tests signing using default algorithms at level T with external TSA
     * and using HTTP basic auth.
     * @throws Exception in case of test error
     */
    @Test
    public void testBaselineTSigning_externalTSA_basicAuthOk() throws Exception {
        LOG.info("testBaselineTSigning_externalTSA_basicAuthOk");
        try {
            final Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            final String username = "user1";
            final String password = "wreaHunbeewNohukotshos1ressagJor";
            setupTimeStampSigner(TSA_WORKER_ID, TSA_WORKER_NAME, time, username, password);
            setupBasicSignerProperties(WORKER_ID, null, null, "PAdES");
            workerSession.setWorkerProperty(WORKER_ID, "SIGNATURE_LEVEL", "BASELINE-T");
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerName=" + TSA_WORKER_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_USERNAME", username);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_PASSWORD", password);
            workerSession.reloadConfiguration(WORKER_ID);
            assertSignedOKPdf(DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), time, DigestAlgorithm.SHA256.getOid(), null, null);
        } finally {
            removeWorker(TSA_WORKER_ID);
        }
    }
    
    /**
     * Tests signing using default algorithms at level T with internal TSA
     * and using HTTP basic auth.
     * @throws Exception in case of test error
     */
    @Test
    public void testBaselineTSigning_internalTSA_basicAuthOk() throws Exception {
        LOG.info("testBaselineTSigning_internalTSA_basicAuthOk");
        try {
            final Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            final String username = "user1";
            final String password = "wreaHunbeewNohukotshos1ressagJor";
            setupTimeStampSigner(TSA_WORKER_ID, TSA_WORKER_NAME, time, username, password);
            setupBasicSignerProperties(WORKER_ID, null, null, "PAdES");
            workerSession.setWorkerProperty(WORKER_ID, "SIGNATURE_LEVEL", "BASELINE-T");
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TSA_WORKER_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_USERNAME", username);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_PASSWORD", password);
            workerSession.reloadConfiguration(WORKER_ID);
            assertSignedOKPdf(DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), time, DigestAlgorithm.SHA256.getOid(), null, null);
        } finally {
            removeWorker(TSA_WORKER_ID);
        }
    }
    
    /**
     * Tests signing using default algorithms at level T with external TSA
     * and using HTTP basic auth with incorrect password should give error.
     * @throws Exception in case of test error
     */
    @Test
    public void testBaselineTSigning_externalTSA_basicAuthIncorrect() throws Exception {
        LOG.info("testBaselineTSigning_externalTSA_basicAuthIncorrect");
        try {
            final Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            final String username = "user1";
            final String password = "wreaHunbeewNohukotshos1ressagJor";
            final String otherPassword = "not_right_password";
            setupTimeStampSigner(TSA_WORKER_ID, TSA_WORKER_NAME, time, username, password);
            setupBasicSignerProperties(WORKER_ID, null, null, "PAdES");
            workerSession.setWorkerProperty(WORKER_ID, "SIGNATURE_LEVEL", "BASELINE-T");
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerName=" + TSA_WORKER_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_USERNAME", username);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_PASSWORD", otherPassword);
            workerSession.reloadConfiguration(WORKER_ID);
            assertSignedNotOk();
        } catch (SignServerException ex) {
            assertTrue("exception: " + ex.getMessage(), ex.getMessage().contains("Processing failure"));
        } finally {
            removeWorker(TSA_WORKER_ID);
        }
    }
    
    /**
     * Tests signing using default algorithms at level T with internal TSA
     * and using HTTP basic auth using incorrect password should give error.
     * @throws Exception in case of test error
     */
    @Test
    public void testBaselineTSigning_internalTSA_basicAuthIncorrect() throws Exception {
        LOG.info("testBaselineTSigning_internalTSA_basicAuthIncorrect");
        try {
            final Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            final String username = "user1";
            final String password = "wreaHunbeewNohukotshos1ressagJor";
            final String otherPassword = "not_right_password";
            setupTimeStampSigner(TSA_WORKER_ID, TSA_WORKER_NAME, time, username, password);
            setupBasicSignerProperties(WORKER_ID, null, null, "PAdES");
            workerSession.setWorkerProperty(WORKER_ID, "SIGNATURE_LEVEL", "BASELINE-T");
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TSA_WORKER_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_USERNAME", username);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_PASSWORD", otherPassword);
            workerSession.reloadConfiguration(WORKER_ID);
            assertSignedNotOk();
        } catch (SignServerException ex) {
            assertTrue("exception: " + ex.getMessage(), ex.getMessage().contains("Processing failure"));
        } finally {
            removeWorker(TSA_WORKER_ID);
        }
    }
    

    /**
     * Tests signing using default algorithms at level B with internal TSA
     * for content time-stamp.
     * @throws Exception in case of test error
     */
    @Test
    public void testBasicSigning_externalTSA_andContentTimeStamp() throws Exception {
        LOG.info("testBasicSigning_externalTSA_andContentTimeStamp");
        try {
            final Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            setupTimeStampSigner(TSA_WORKER_ID, TSA_WORKER_NAME, time, null, null);
            setupBasicSignerProperties(WORKER_ID, null, null, "PAdES");
            workerSession.setWorkerProperty(WORKER_ID, "SIGNATURE_LEVEL", "BASELINE-B");
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerName=" + TSA_WORKER_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "ADD_CONTENT_TIMESTAMP", "true");
            workerSession.reloadConfiguration(WORKER_ID);
            assertSignedOKPdf(DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), null, null, time, DigestAlgorithm.SHA256.getOid());
        } finally {
            removeWorker(TSA_WORKER_ID);
        }
    }

    /**
     * Tests signing using default algorithms at level T with internal TSA and
     * additionally also with content time-stamp.
     * @throws Exception in case of test error
     */
    @Test
    public void testBaselineTSigning_externalTSA_andContentTimeStamp() throws Exception {
        LOG.info("testBaselineTSigning_externalTSA_andContentTimeStamp");
        try {
            final Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            setupTimeStampSigner(TSA_WORKER_ID, TSA_WORKER_NAME, time, null, null);
            setupBasicSignerProperties(WORKER_ID, null, null, "PAdES");
            workerSession.setWorkerProperty(WORKER_ID, "SIGNATURE_LEVEL", "BASELINE-T");
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerName=" + TSA_WORKER_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "ADD_CONTENT_TIMESTAMP", "true");
            workerSession.reloadConfiguration(WORKER_ID);
            assertSignedOKPdf(DigestAlgorithm.SHA256, SignatureAlgorithm.RSA_SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), time, DigestAlgorithm.SHA256.getOid(), time, DigestAlgorithm.SHA256.getOid());
        } finally {
            removeWorker(TSA_WORKER_ID);
        }
    }
    
}
