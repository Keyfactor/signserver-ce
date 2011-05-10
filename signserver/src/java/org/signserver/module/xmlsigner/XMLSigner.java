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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.persistence.EntityManager;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.util.CertTools;
import org.signserver.common.ArchiveData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericServletRequest;
import org.signserver.common.GenericServletResponse;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.ISignRequest;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.signers.BaseSigner;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

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

    private static final Logger LOG = Logger.getLogger(XMLSigner.class.getName());

    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
    }

    public ProcessResponse processData(ProcessRequest signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {

        ProcessResponse signResponse;
        ISignRequest sReq = (ISignRequest) signRequest;

        // Check that the request contains a valid GenericSignRequest object with a byte[].
        if (!(signRequest instanceof GenericSignRequest)) {
            throw new IllegalRequestException("Recieved request wasn't a expected GenericSignRequest.");
        }
        if (!(sReq.getRequestData() instanceof byte[])) {
            throw new IllegalRequestException("Recieved request data wasn't a expected byte[].");
        }

        byte[] data = (byte[]) sReq.getRequestData();
        byte[] fpbytes = CertTools.generateSHA1Fingerprint(data);
        String fp = new String(Hex.encode(fpbytes));



        String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        XMLSignatureFactory fac;
        try {
            fac = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());
        } catch (InstantiationException e) {
            throw new SignServerException("Problem with JSR105 provider", e);
        } catch (IllegalAccessException e) {
            throw new SignServerException("Problem with JSR105 provider", e);
        } catch (ClassNotFoundException e) {
            throw new SignServerException("Problem with JSR105 provider", e);
        }

        // Get certificate chain and signer certificate
        Collection<Certificate> certs = this.getSigningCertificateChain();
        if (certs == null) {
            throw new IllegalArgumentException("Null certificate chain. This signer needs a certificate.");
        }
        List<X509Certificate> x509CertChain = new LinkedList<X509Certificate>();
        for (Certificate cert : certs) {
            if (cert instanceof X509Certificate) {
                x509CertChain.add((X509Certificate) cert);
                LOG.debug("Adding to chain: " + ((X509Certificate) cert).getSubjectDN());
            }
        }
        Certificate cert = this.getSigningCertificate();
        LOG.debug("SigningCert: " + ((X509Certificate) cert).getSubjectDN());

        // Private key
        PrivateKey privKey = getCryptoToken().getPrivateKey(ICryptoToken.PURPOSE_SIGN);

        SignedInfo si;
        try {
            Reference ref = fac.newReference("",
                    fac.newDigestMethod(DigestMethod.SHA1, null),
                    Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (XMLStructure) null)),
                    null, null);

            si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (XMLStructure) null),
                    fac.newSignatureMethod(getSignatureMethod(privKey), null),
                    Collections.singletonList(ref));

        } catch (InvalidAlgorithmParameterException ex) {
            throw new SignServerException("XML signing algorithm error", ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new SignServerException("XML signing algorithm error", ex);
        }



        KeyInfoFactory kif = fac.getKeyInfoFactory();
        X509Data x509d = kif.newX509Data(x509CertChain);

        List<XMLStructure> kviItems = new LinkedList<XMLStructure>();
        kviItems.add(x509d);
        KeyInfo ki = kif.newKeyInfo(kviItems);

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc;

        try {
            doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(data));
        } catch (SAXException ex) {
            throw new SignServerException("Document parsing error", ex);
        } catch (ParserConfigurationException ex) {
            throw new SignServerException("Document parsing error", ex);
        } catch (IOException ex) {
            throw new SignServerException("Document parsing error", ex);
        }
        DOMSignContext dsc = new DOMSignContext(privKey, doc.getDocumentElement());

        XMLSignature signature = fac.newXMLSignature(si, ki);
        try {
            signature.sign(dsc);
        } catch (MarshalException ex) {
            throw new SignServerException("Signature generation error", ex);
        } catch (XMLSignatureException ex) {
            throw new SignServerException("Signature generation error", ex);
        }

        ByteArrayOutputStream bout = new ByteArrayOutputStream();

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans;
        try {
            trans = tf.newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(bout));
        } catch (TransformerConfigurationException ex) {
            throw new SignServerException("XML transformation error", ex);
        } catch (TransformerException ex) {
            throw new SignServerException("XML transformation error", ex);
        }

        final byte[] signedbytes = bout.toByteArray();

        if (signRequest instanceof GenericServletRequest) {
            signResponse = new GenericServletResponse(sReq.getRequestID(), signedbytes, getSigningCertificate(), fp, new ArchiveData(signedbytes), "text/xml");
        } else {
            signResponse = new GenericSignResponse(sReq.getRequestID(), signedbytes, getSigningCertificate(), fp, new ArchiveData(signedbytes));
        }
        return signResponse;
    }

    private static String getSignatureMethod(final PrivateKey key)
            throws NoSuchAlgorithmException {
        String result;
        
        if("DSA".equals(key.getAlgorithm())) {
            result = SignatureMethod.DSA_SHA1;
        } else if("RSA".equals(key.getAlgorithm())) {
            result = SignatureMethod.RSA_SHA1;
        } else {
            throw new NoSuchAlgorithmException("XMLSigner does not support algorithm: " + key.getAlgorithm());
        }
        
        return result;
    }
}
