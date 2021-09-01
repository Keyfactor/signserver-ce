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
package org.signserver.test.random.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Random;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.*;
import org.signserver.common.*;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.test.random.FailedException;
import org.signserver.test.random.Task;
import org.signserver.test.random.WorkerSpec;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Signs a sample document.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class Sign implements Task {

    private static final Logger LOG = Logger.getLogger(Sign.class);

    private final WorkerSpec signer;
    private final ProcessSessionRemote workerSession;
    private final Random random;
    private int counter;
    private final RequestContextPreProcessor preProcessor;

    private static final String TESTXML1 = "<doc>Some sample XML to sign</doc>";

    public Sign(final WorkerSpec signerId, final ProcessSessionRemote workerSession, final Random random, final RequestContextPreProcessor preProcessor) {
        this.signer = signerId;
        this.workerSession = workerSession;
        this.random = random;
        this.preProcessor = preProcessor;
    }

    @Override
    public void run() throws FailedException {
        LOG.debug(">run");
        try {
            final int reqid = counter++;
            LOG.info("Worker " + signer + " signing: " + counter);
            process(signer, reqid);
        } catch (IllegalRequestException ex) {
            throw new FailedException("Illegal request", ex);
        } catch (CryptoTokenOfflineException ex) {
            throw new FailedException("Worker offline", ex);
        } catch (SignServerException ex) {
            throw new FailedException("Generic error: " + ex.getMessage(), ex);
        }
        LOG.debug("<run");
    }

    private void process(final WorkerSpec signer, final int reqid) throws FailedException, IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        final RemoteRequestContext requestContext = new RemoteRequestContext();
        if (preProcessor != null) {
            preProcessor.preProcess(requestContext);
        }
        switch (signer.getWorkerType()) {
            case xml: {
                // Process
                final GenericSignRequest signRequest = new GenericSignRequest(reqid, TESTXML1.getBytes());
                final ProcessResponse response = workerSession.process(new WorkerIdentifier(signer.getWorkerId()), signRequest, requestContext);

                // Check result
                GenericSignResponse res = (GenericSignResponse) response;
                final byte[] data = res.getProcessedData();
                // Check that we got a signed XML back
                String xml = new String(data);
                if (!xml.contains("xmldsig")) {
                    throw new FailedException("Response was not signed: \"" + xml + "\"");
                }
                validateXMLSignature(xml);
                break;
            }
            case tsa: {
                try {
                    // Process
                    final TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
                    final int nonce = random.nextInt();
                    final TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(nonce));
                    byte[] requestBytes = timeStampRequest.getEncoded();

                    GenericSignRequest signRequest =
                            new GenericSignRequest(reqid, requestBytes);
                    final GenericSignResponse res = (GenericSignResponse) workerSession.process(new WorkerIdentifier(signer.getWorkerId()), signRequest, requestContext);

                    // Check result
                    if (reqid != res.getRequestID()) {
                        throw new FailedException("Expected request id: " + reqid + " but was " + res.getRequestID());
                    }

                    final Certificate signercert = res.getSignerCertificate();
                    if (signercert == null) {
                        throw new FailedException("No certificate returned");
                    }

                    final TimeStampResponse timeStampResponse = new TimeStampResponse(res.getProcessedData());
                    timeStampResponse.validate(timeStampRequest);

                    if (timeStampResponse.getStatus() != PKIStatus.GRANTED) {
                        throw new FailedException("Token was not granted: " + timeStampResponse.getStatus());
                    }

                    if (timeStampResponse.getTimeStampToken() == null) {
                        throw new FailedException("No token returned");
                    }
                    break;
                } catch (TSPException ex) {
                    LOG.error("Verification error", ex);
                    throw new FailedException("Response could not be verified: " + ex.getMessage());
                } catch (IOException ex) {
                    LOG.error("Could not create request", ex);
                    throw new FailedException("Could not create request: " + ex.getMessage());
                }
            }
            default:
                throw new IllegalRequestException("Unsupported workerType: " + signer.getWorkerType());
        }
    }

    /**
     * Validates the XML signature using a certificate in it.
     * Does not check certificate in any other way.
     * @param xml document to check
     * @throws FailedException in case validation failed
     * @throws SignServerException in case testing failed in other ways
     */
    private void validateXMLSignature(String xml) throws FailedException, SignServerException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);

        Document doc;
        try {
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

            doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        } catch (ParserConfigurationException | SAXException | IOException ex) {
            throw new FailedException("Document parsing error", ex);
        }
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            throw new FailedException("No Signature found");
        }

        String providerName = System.getProperty("jsr105Provider", "org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI");
        XMLSignatureFactory fac;
        try {
            fac = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            throw new SignServerException("Problem with JSR105 provider", e);
        }

        DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(), nl.item(0));

        // enable secure validation
        valContext.setProperty("org.apache.jcp.xml.dsig.secureValidation", Boolean.TRUE);

        try {
            XMLSignature signature = fac.unmarshalXMLSignature(valContext);
            if (!signature.validate(valContext)) {
                throw new FailedException("Signature verification failed");
            }
        } catch (MarshalException | XMLSignatureException ex) {
            throw new FailedException("XML signature validation error", ex);
        }
    }

    /** Key selector just using the first certificate of right type. */
    static class X509KeySelector extends KeySelector {

        @Override
        public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose, AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {
            Iterator ki = keyInfo.getContent().iterator();
            while (ki.hasNext()) {
                XMLStructure info = (XMLStructure) ki.next();
                if (!(info instanceof X509Data)) {
                    continue;
                }
                X509Data x509Data = (X509Data) info;
                Iterator xi = x509Data.getContent().iterator();
                while (xi.hasNext()) {
                    Object o = xi.next();
                    if (!(o instanceof X509Certificate)) {
                        continue;
                    }
                    final PublicKey key = ((X509Certificate) o).getPublicKey();
                    if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
                        return () -> key;
                    }
                }
            }
            throw new KeySelectorException("No key found!");
        }
        private boolean algEquals(String algURI, String algName) {
            if ((algName.equalsIgnoreCase("DSA") &&
                algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) ||
                (algName.equalsIgnoreCase("RSA") &&
                algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1))) {
                return true;
            } else {
                return false;
            }
        }
    }

}
