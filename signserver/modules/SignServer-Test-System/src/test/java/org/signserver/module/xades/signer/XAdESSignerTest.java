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
package org.signserver.module.xades.signer;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.util.List;
import javax.ejb.EJBException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.log4j.Logger;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.testutils.ModulesTestCase;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.impl.DefaultTimeStampVerificationProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.verification.SignatureSpecificVerificationOptions;
import xades4j.verification.XAdESVerificationResult;
import xades4j.verification.XadesVerificationProfile;
import xades4j.verification.XadesVerifier;
import org.signserver.ejb.interfaces.WorkerSession;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * System tests for the XAdESSigner.
 *
 * Note: Unit tests should be placed in the SignServer-Module-XAdES project.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class XAdESSignerTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(XAdESSignerTest.class);

    private static final int WORKER_ID = 9901;
    private static final String WORKER_NAME = "TestXAdESSigner";
    private static final int TS_ID = 9902;
    private static final String TS_NAME = "TestTimeStampSigner";

    private final WorkerSession workerSession = getWorkerSession();
    private final ProcessSessionRemote processSession = getProcessSession();

    private void internalSigningAndVerify(String tsaDigestAlgorithm, String acceptedTSADigestAlgorithm) throws Exception {
        try {

            addTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner(XAdESSigner.class.getName(), WORKER_ID, WORKER_NAME, true);

            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTEDALGORITHMS", acceptedTSADigestAlgorithm);

            workerSession.setWorkerProperty(WORKER_ID, "XADESFORM", "T");
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            if (tsaDigestAlgorithm != null) {
                workerSession.setWorkerProperty(WORKER_ID, "TSA_DIGESTALGORITHM", tsaDigestAlgorithm);
            }

            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            GenericSignRequest request = new GenericSignRequest(100, "<test100/>".getBytes(StandardCharsets.UTF_8));
            GenericSignResponse response = (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_ID), request, new RemoteRequestContext());

            byte[] data = response.getProcessedData();
            final String signedXml = new String(data);
            LOG.debug("signedXml: " + signedXml);

            // Validation: setup
            CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(workerSession.getSignerCertificateChain(new WorkerIdentifier(WORKER_ID))));
            KeyStore trustAnchors = KeyStore.getInstance("JKS");
            trustAnchors.load(null, "foo123".toCharArray());
            final List<Certificate> signerCertificateChain =
                workerSession.getSignerCertificateChain(new WorkerIdentifier(WORKER_ID));
            final List<Certificate> tsSignerCertificateChain =
                workerSession.getSignerCertificateChain(new WorkerIdentifier(TS_ID));
            trustAnchors.setCertificateEntry("signerIssuer", signerCertificateChain.get(signerCertificateChain.size() - 1));
            trustAnchors.setCertificateEntry("tsIssuer", tsSignerCertificateChain.get(tsSignerCertificateChain.size() - 1));

            CertificateValidationProvider certValidator = new PKIXCertificateValidationProvider(trustAnchors, false, certStore);

            XadesVerificationProfile p =
                    new XadesVerificationProfile(certValidator).withTimeStampTokenVerifier(DefaultTimeStampVerificationProvider.class);
            XadesVerifier verifier = p.newVerifier();

            // Validation: parse
            final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            final DocumentBuilder builder = factory.newDocumentBuilder();
            final Document doc = builder.parse(new ByteArrayInputStream(data));
            Element node = doc.getDocumentElement();

            XAdESVerificationResult r = verifier.verify(node, new SignatureSpecificVerificationOptions());

            LOG.debug("signature form: " + r.getSignatureForm().name());
            assertEquals("T", r.getSignatureForm().name());
            assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", r.getSignatureAlgorithmUri());
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }

    /**
     * Tests XADES-T signing with default TSA_DIGEST_ALGORITHM algorithm.
     */
    @Test
    public void testBasicSigningXAdESFormT_TSA_DIGEST_ALGO_Default_SHA256() throws Exception {
        LOG.info("testBasicSigningXAdESFormT_TSA_DIGEST_ALGO_Default_SHA256");
        internalSigningAndVerify(null, "SHA256");
    }

    /**
     * Tests XADES-T signing with SHA-1 TSA_DIGEST_ALGORITHM algorithm.
     */
    @Test
    public void testBasicSigningXAdESFormT_TSA_DIGEST_ALGO_SHA1() throws Exception {
        LOG.info("testBasicSigningXAdESFormT_TSA_DIGEST_ALGO_SHA1");
        internalSigningAndVerify("SHA1", "SHA1");
    }

    /**
     * Tests XADES-T signing with SHA-512 TSA_DIGEST_ALGORITHM algorithm.
     */
    @Test
    public void testBasicSigningXAdESFormT_TSA_DIGEST_ALGO_SHA512() throws Exception {
        LOG.info("testBasicSigningXAdESFormT_TSA_DIGEST_ALGO_SHA512");
        internalSigningAndVerify("SHA512", "SHA512");
    }

    /**
     * Tests XADES-T signing with illegal TSA_DIGEST_ALGORITHM algorithm and
     * check if fails.
     */
    @Test
    public void testBasicSigningXAdESFormT_Illegal_TSA_DIGEST_ALGO() throws Exception {
        LOG.info("testBasicSigningXAdESFormT_Illegal_TSA_DIGEST_ALGO");
        try {
            internalSigningAndVerify("Illegal_TSA_Digest_Algo", "SHA512");
            fail("It should have been failed");
        } catch (EJBException ex) {
            if (ex.getMessage() != null) { // On glassfish server, ex.getMessage() is NULL
                assertTrue(ex.getMessage(), ex.getMessage().contains("Unsupported TSA digest algorithm"));
            }
        }
    }

}
