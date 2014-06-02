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
import java.security.KeyStore;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.log4j.Logger;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.ejb.interfaces.IWorkerSession;
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

    private final IWorkerSession workerSession = getWorkerSession();

    @Test
    public void testBasicSigningXAdESFormT() throws Exception {
        LOG.info("testBasicSigningXAdESFormT");
        try {

            addSoftTimeStampSigner(TS_ID, TS_NAME);
            addSigner(XAdESSigner.class.getName(), WORKER_ID, WORKER_NAME);
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(WORKER_ID, "XADESFORM", "T");
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            RequestContext requestContext = new RequestContext();
            requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");
            GenericSignRequest request = new GenericSignRequest(100, "<test100/>".getBytes("UTF-8"));
            GenericSignResponse response = (GenericSignResponse) workerSession.process(WORKER_ID, request, requestContext);

            byte[] data = response.getProcessedData();
            final String signedXml = new String(data);
            LOG.debug("signedXml: " + signedXml);

            // Validation: setup
            CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(workerSession.getSignerCertificateChain(WORKER_ID)));
            KeyStore trustAnchors = KeyStore.getInstance("JKS");
            trustAnchors.load(null, "foo123".toCharArray());
            trustAnchors.setCertificateEntry("signerIssuer", workerSession.getSignerCertificateChain(WORKER_ID).get(1));
            trustAnchors.setCertificateEntry("tsIssuer", workerSession.getSignerCertificateChain(TS_ID).get(1));

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

}
