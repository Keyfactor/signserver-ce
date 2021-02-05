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
package org.signserver.module.xmlvalidator;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.List;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static junit.framework.TestCase.fail;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.util.CertTools;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.GenericValidationResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;
import org.signserver.common.data.DocumentValidationRequest;
import org.signserver.common.data.DocumentValidationResponse;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.validationservice.common.Validation;
import org.xml.sax.SAXParseException;

/**
 * Unit tests for the XMLValidator class.
 *
 * System tests (and other tests) are available in the Test-System project.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class XMLValidatorUnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(XMLValidatorUnitTest.class);

    private static final String SIGNER2_ISSUERDN = "CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE";
    private static final String SIGNER2_SUBJECTDN = "CN=Signer 2,OU=Testing,O=SignServer,C=SE";


    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static MockedCryptoToken generateToken() throws Exception {
        final KeyPair signerKeyPair = CryptoUtils.generateRSA(1024);
        final Certificate[] certChain =
                new Certificate[] {new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSelfSignKeyPair(signerKeyPair).
                        setSignatureAlgorithm("SHA1withRSA")
                        .build())};
        final Certificate signerCertificate = certChain[0];
        return new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), "BC");
    }

    /**
     * Test validating with a correct signature and certificate.
     * 
     * @param reqid Request ID to use
     * @param workerId Worker ID
     * @param xml Document to validate
     * @param expectedSubjectDN Expected subject DN
     * @param expectedIssuerDN Expected issuer DN
     * @throws Exception
     */
    private void testSigOkCertOk(final int reqid, final String xml,
            final String expectedSubjectDN, final String expectedIssuerDN) throws Exception {

        WorkerConfig config = new WorkerConfig();
        config.setProperty(WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        config.setProperty("VALIDATIONSERVICEWORKER", "AnyValueAsWeMockedThis");

        XMLValidator instance = new MockedXMLValidator(new MockedWorkerSession());
        instance.init(4711, config, null, null);
        final RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");

        System.err.println(instance.getFatalErrors(null));
        
        DocumentValidationRequest request = new DocumentValidationRequest(100, ModulesTestCase.createRequestData(xml.getBytes(StandardCharsets.UTF_8)));
        DocumentValidationResponse res = (DocumentValidationResponse) instance.processData(request, requestContext);

        assertTrue("valid document", res.isValid());

        // Check certificate and path
        Certificate signercert = res.getCertificateValidationResponse().getValidation().getCertificate();
        assertEquals("Signer certificate", expectedSubjectDN, CertTools.getSubjectDN(signercert));
        List<Certificate> caChain = res.getCertificateValidationResponse().getValidation().getCAChain();
        assertEquals("ca certificate 0", expectedIssuerDN, CertTools.getSubjectDN(caChain.get(0)));
        assertEquals("caChain length", 1, caChain.size());
        LOG.info("Status message: " + res.getCertificateValidationResponse().getValidation().getStatusMessage());
        assertEquals(Validation.Status.VALID, res.getCertificateValidationResponse().getValidation().getStatus());
    }

    @Test
    public void testSigOkCertOk() throws Exception {
        testSigOkCertOk(13, XMLValidatorTestData.TESTXML1, SIGNER2_SUBJECTDN, SIGNER2_SUBJECTDN);
    }

    /**
     * Tests that a document with a DOCTYPE is not allowed.
     * @throws Exception
     */
    @Test
    @SuppressWarnings("ThrowableResultIgnored")
    public void testDTDNotAllowed() throws Exception {
        LOG.info("testDTDNotAllowed");
        try {
            testSigOkCertOk(13, XMLValidatorTestData.TESTXML1_WITH_DOCTYPE, SIGNER2_SUBJECTDN, SIGNER2_SUBJECTDN);
            fail("Should have thrown IllegalRequestException as the document contained a DTD");
        } catch (SignServerException expected) { // TODO: Bug in XMLValidator as it actually should be IllegalRequestException
            if (expected.getCause() instanceof SAXParseException) {
                if (!expected.getCause().getMessage().contains("DOCTYPE")) {
                    LOG.error("Wrong exception message", expected);
                    fail("Should be error about doctype: " + expected.getMessage());
                }
            } else {
                LOG.error("Wrong exception cause", expected);
                fail("Expected SAXParseException but was: " + expected);
            }
        }
    }

}
