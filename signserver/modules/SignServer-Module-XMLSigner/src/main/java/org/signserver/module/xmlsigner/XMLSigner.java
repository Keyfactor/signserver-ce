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
package org.signserver.module.xmlsigner;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.server.signers.BaseSigner;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;
import org.signserver.server.IServices;

/**
 * A Signer signing XML documents.
 *
 * Implements a ISigner and have the following properties:
 * No properties yet
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class XMLSigner extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(XMLSigner.class);
    private static final String CONTENT_TYPE = "text/xml";

    // Property constants
    public static final String SIGNATUREALGORITHM = "SIGNATUREALGORITHM";    
    public static final String DIGESTALGORITHM = "DIGESTALGORITHM";    
    private static final String SIGNATURE_ALGORITHM_PREFIX = "with";     
    private static final String DIGEST_METHOD_URI_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    
    /**
     * Addional signature methods not yet covered by
     * javax.xml.dsig.SignatureMethod
     *
     * Defined in RFC 4051 {@link http://www.ietf.org/rfc/rfc4051.txt}
     */
    private static final String SIGNATURE_METHOD_RSA_SHA256 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private static final String SIGNATURE_METHOD_RSA_SHA384 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    private static final String SIGNATURE_METHOD_RSA_SHA512 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    private static final String SIGNATURE_METHOD_ECDSA_SHA1 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
    private static final String SIGNATURE_METHOD_ECDSA_SHA256 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    private static final String SIGNATURE_METHOD_ECDSA_SHA384 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    private static final String SIGNATURE_METHOD_ECDSA_SHA512 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
    private static final String SIGNATURE_METHOD_DSA_SHA256 =
            "http://www.w3.org/2009/xmldsig11#dsa-sha256";

    private String signatureAlgorithm;
    private String digestAlgorithmString;
    private String digestMethod;
    private LinkedList<String> configErrors;

    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        // Configuration errors
        configErrors = new LinkedList<>();

        // Get the signature algorithm
        signatureAlgorithm = config.getProperty(SIGNATUREALGORITHM, DEFAULT_NULL);
        
        // Get the digest algorithm
        digestAlgorithmString = config.getProperty(DIGESTALGORITHM, DEFAULT_NULL);
        
        // Get the digest method from digest algorithm
        if (digestAlgorithmString != null) {
            try {
                digestMethod = getDigestMethodFromDigestAlgorithmString(digestAlgorithmString);
            } catch (NoSuchAlgorithmException ex) {
                configErrors.add("XMLSigner does not support digest algorithm: " + digestAlgorithmString);
            }
        }
    }

    @Override
    public Response processData(Request signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {

        // Check that the request contains a valid GenericSignRequest object
        // with a byte[].
        if (!(signRequest instanceof SignatureRequest)) {
            throw new IllegalRequestException(
                    "Received request wasn't an expected GenericSignRequest.");
        }
        
        if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }
        
        final SignatureRequest sReq = (SignatureRequest) signRequest;
        String archiveId = createArchiveId(new byte[0], (String) requestContext.get(RequestContext.TRANSACTION_ID));

        String providerName = System.getProperty("jsr105Provider", "org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI");
        XMLSignatureFactory fac;
        try {
            fac = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            throw new SignServerException("Problem with JSR105 provider", e);
        }

        final ReadableData requestData = sReq.getRequestData();
        final WritableData responseData = sReq.getResponseData();
        Certificate cert;
        Document doc;
        ICryptoInstance crypto = null;
        try {
            crypto = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, signRequest, requestContext);

            // Get certificate chain and signer certificate
            final List<Certificate> certs = getSigningCertificateChain(crypto);
            if (certs == null) {
                throw new IllegalArgumentException("Null certificate chain. This signer needs a certificate.");
            }
            List<X509Certificate> x509CertChain = new LinkedList<>();
            for (Certificate c : includedCertificates(certs)) {
                if (c instanceof X509Certificate) {
                    x509CertChain.add((X509Certificate) c);
                    LOG.debug("Adding to chain: " + ((X509Certificate) c).getSubjectDN());
                }
            }
            cert = this.getSigningCertificate(crypto);
            if (LOG.isDebugEnabled()) {
                LOG.debug("SigningCert: " + ((X509Certificate) cert).getSubjectDN());
            }

            // Private key
            final PrivateKey privKey = crypto.getPrivateKey();

            SignedInfo si;
            try {
                final String sigAlg = signatureAlgorithm == null ? getDefaultSignatureAlgorithm(privKey) : signatureAlgorithm;
                
                // find digest method if DIGESTALGORITHM not provided                               
                if (digestMethod == null) {
                    digestMethod = getDefaultDigestMethodFromSignatureAlgorithm((sigAlg));
                }
                
                Reference ref = fac.newReference("",
                        fac.newDigestMethod(digestMethod, null),
                        Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (XMLStructure) null)),
                        null, null);

                si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (XMLStructure) null),
                        fac.newSignatureMethod(getSignatureMethod(sigAlg), null),
                        Collections.singletonList(ref));

            } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException ex) {
                throw new SignServerException("XML signing algorithm error", ex);
            }

            KeyInfo ki = null;

            if (!x509CertChain.isEmpty()) {
                KeyInfoFactory kif = fac.getKeyInfoFactory();
                X509Data x509d = kif.newX509Data(x509CertChain);

                List<XMLStructure> kviItems = new LinkedList<>();
                kviItems.add(x509d);
                ki = kif.newKeyInfo(kviItems);
            }

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);

            try (InputStream in = requestData.getAsInputStream()) {
                // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
                // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
                dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);

                // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
                // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
                dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

                // Xerces 2 only - http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl
                dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

                doc = dbf.newDocumentBuilder().parse(in);
            } catch (SAXException ex) {
                throw new IllegalRequestException("Document parsing error", ex);
            } catch (ParserConfigurationException | IOException ex) {
                throw new SignServerException("Document parsing error", ex);
            }
            DOMSignContext dsc = new DOMSignContext(privKey, doc.getDocumentElement());
            dsc.setProperty("org.jcp.xml.dsig.internal.dom.SignatureProvider", crypto.getProvider());

            XMLSignature signature = fac.newXMLSignature(si, ki);
            try {
                signature.sign(dsc);
            } catch (MarshalException | XMLSignatureException ex) {
                throw new SignServerException("Signature generation error", ex);
            }
        } finally {
            releaseCryptoInstance(crypto, requestContext);
        }

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans;
        try (OutputStream out = responseData.getAsOutputStream()) {
            trans = tf.newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(out));
        } catch (TransformerException | IOException ex) {
            throw new SignServerException("XML transformation error", ex);
        }

        final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST, CONTENT_TYPE, requestData, archiveId), 
                    new DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, responseData.toReadableData(), archiveId));

        // The client can be charged for the request
        requestContext.setRequestFulfilledByWorker(true);

        return new SignatureResponse(sReq.getRequestID(), responseData,
                cert,
                archiveId, archivables, CONTENT_TYPE);
    }

    /**
     * Get an XMLSec URI for a given signature algorithm in BC style.
     *
     * @param sigAlg Signature algorithm name in BC style
     * @return The URI for the algo in XMLSec.
     * @throws NoSuchAlgorithmException
     */
    private static String getSignatureMethod(final String sigAlg)
            throws NoSuchAlgorithmException {
        String result;

        if ("SHA1withDSA".equals(sigAlg)) {
            result = SignatureMethod.DSA_SHA1;
        } else if ("SHA256withDSA".equals(sigAlg)) {
            result = SIGNATURE_METHOD_DSA_SHA256;
        } else if ("SHA1withRSA".equals(sigAlg)) {
            result = SignatureMethod.RSA_SHA1;
        } else if ("SHA256withRSA".equals(sigAlg)) {
            result = SIGNATURE_METHOD_RSA_SHA256;
        } else if ("SHA384withRSA".equals(sigAlg)) {
            result = SIGNATURE_METHOD_RSA_SHA384;
        } else if ("SHA512withRSA".equals(sigAlg)) {
            result = SIGNATURE_METHOD_RSA_SHA512;
        } else if ("SHA1withECDSA".equals(sigAlg)) {
            result = SIGNATURE_METHOD_ECDSA_SHA1;
        } else if ("SHA256withECDSA".equals(sigAlg)) {
            result = SIGNATURE_METHOD_ECDSA_SHA256;
        } else if ("SHA384withECDSA".equals(sigAlg)) {
            result = SIGNATURE_METHOD_ECDSA_SHA384;
        } else if ("SHA512withECDSA".equals(sigAlg)) {
            result = SIGNATURE_METHOD_ECDSA_SHA512;
        } else {
            throw new NoSuchAlgorithmException("XMLSigner does not support algorithm: " + sigAlg);
        }

        return result;
    }

    /**
     * Return the default signature algo name given the private key.
     *
     * @param privKey
     * @return
     */
    private String getDefaultSignatureAlgorithm(final PrivateKey privKey) {
        final String result;

        if (privKey instanceof DSAPrivateKey) {
            result = "SHA256withDSA";
        } else if (privKey instanceof ECPrivateKey || "EC".equalsIgnoreCase(privKey.getAlgorithm())) {
            result = "SHA256withECDSA";
        } else {
            result = "SHA256withRSA";
        }

        return result;
    }

    /**
     * Return the default digest method URI matching the given signature algorithm.
     *
     * @param sigAlg
     * @return
     */
    private String getDefaultDigestMethodFromSignatureAlgorithm(String sigAlg) throws NoSuchAlgorithmException {
        String result;

        // Extract digest algorithm from signature algorithm
        String digestAlg = sigAlg.substring(0, sigAlg.indexOf(SIGNATURE_ALGORITHM_PREFIX));

        switch (digestAlg) {
            case "SHA1":
                result = DigestMethod.SHA1;
                break;
            case "SHA256":
                result = DigestMethod.SHA256;
                break;
            case "SHA384":
                result = DIGEST_METHOD_URI_SHA384;
                break;
            case "SHA512":
                result = DigestMethod.SHA512;
                break;
            default:
                throw new NoSuchAlgorithmException("XMLSigner does not support signature algorithm: " + sigAlg);
        }

        return result;
    }

    /**
     * Return the digest method URI matching the given digest algorithm.
     *
     * @param digestAlgorithm
     * @return
     */
    private String getDigestMethodFromDigestAlgorithmString(String digestAlgorithm) throws NoSuchAlgorithmException {
        String result;

        switch (digestAlgorithm) {
            case "SHA1":
            case "SHA-1":
                result = DigestMethod.SHA1;
                break;
            case "SHA256":
            case "SHA-256":
                result = DigestMethod.SHA256;
                break;
            case "SHA384":
            case "SHA-384":
                result = DIGEST_METHOD_URI_SHA384;
                break;
            case "SHA512":
            case "SHA-512":
                result = DigestMethod.SHA512;
                break;
            case "RIPEMD160":
            case "RIPEMD-160":
                result = DigestMethod.RIPEMD160;
                break;
            default:
                throw new NoSuchAlgorithmException("XMLSigner does not support digest algorithm: " + digestAlgorithm);
        }
        return result;
    }
    
    @Override
    protected List<String> getFatalErrors(final IServices services) {
        final LinkedList<String> errors = new LinkedList<>(super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }
}
