/************************************************************************
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
 *
 * Copyright 2008 Sun Microsystems, Inc. All rights reserved.
 * Copyright 2009 IBM. All rights reserved.
 *
 * Use is subject to license terms.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0. You can also
 * obtain a copy of the License at http://odftoolkit.org/docs/license.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ************************************************************************/
package org.odftoolkit.odfdom.pkg.signature;

import java.security.Key;
import java.security.KeyException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;

/**
 * Key selector that searches for signing key inside document signature
 * 
 * @author aziz.goktepe (aka rayback_2)
 *
 * patch originally created for SignServer project {@link http://www.signserver.org}
 */
public class ODFKeySelector extends KeySelector implements KeySelectorResult {

    private X509Certificate signingCertificate;
    private PublicKey signingPublicKey;
    private DocumentSignature documentSignature;

    public ODFKeySelector(DocumentSignature pDocumentSignature) {
        this.documentSignature = pDocumentSignature;
    }

    /**
     * returns signing certificate if found
     *
     * @return
     */
    public X509Certificate getSigningCertificate() {
        return signingCertificate;
    }

    /**
     * returns document signature object associated with this keyselector
     *
     */
    public DocumentSignature getPackageDigitalSignature() {
        return this.documentSignature;
    }

    /**
     *
     * @return public key of signer. If getSigningCertificate() is not null ,
     *         this is the public key of certificate found in package from
     *         certificate part , or from x509Data inside signature xml.
     *
     *         If getSigningCertificate() is null, this is public key found from
     *         KeyValue from KeyInfo of in signature xml.
     */
    public PublicKey getSigningPublicKey() {
        return signingPublicKey;
    }

    @Override
    /*
     * tries to find signing certificate by looking into X509Data inside the
     * signature.If it can't find signing certificate from X509Data
     * then it retrieves public key from KeyValue
     */
    public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose,
            AlgorithmMethod method, XMLCryptoContext context)
            throws KeySelectorException {

        SignatureMethod signatureMethod = (SignatureMethod) method;
        X509Certificate cert = null;

        // try to get certificate from x509data
        cert = tryGetSigningCertificateFromX509Data(keyInfo, signatureMethod);
        if (cert != null) {
            this.signingCertificate = cert;
            this.signingPublicKey = cert.getPublicKey();
            return this;
        }

        // try get public key from KeyValue
        final PublicKey pKey = getPublicKeyFromKeyInfo(keyInfo, signatureMethod);
        if (pKey != null) {
            this.signingPublicKey = pKey;
            return this;
        }

        return null;
    }

    /**
     * retrieves public key from KeyValue
     *
     * @return PublicKey if found, null otherwise
     * @throws KeySelectorException
     */
    private PublicKey getPublicKeyFromKeyInfo(KeyInfo keyInfo,
            SignatureMethod method) throws KeySelectorException {

        for (Object o1 : keyInfo.getContent()) {
            if (o1 instanceof KeyValue) {
                KeyValue data = (KeyValue) o1;
                PublicKey retVal;
                try {
                    retVal = data.getPublicKey();
                } catch (KeyException e) {
                    throw new KeySelectorException(e);
                }

                // check if algorithm fits
                if (!matchingAlgorithms(retVal.getAlgorithm(), method.getAlgorithm())) {
                    throw new KeySelectorException(
                            "algorithm specified by public key found in KeyValue is not supported. Specified algorithm is : " + retVal.getAlgorithm());
                }
            }
        }

        return null;
    }

    /**
     * tries to find signing certificate by looking into X509Data inside the
     * signature 
     *
     * @param method
     * @return signing Certificate if found, null otherwise
     * @throws KeySelectorException
     */
    private X509Certificate tryGetSigningCertificateFromX509Data(
            KeyInfo keyInfo, SignatureMethod method)
            throws KeySelectorException {

        // find all certificates in x509data
        List<X509Certificate> foundCerts = new ArrayList<X509Certificate>();

        for (Object o1 : keyInfo.getContent()) {
            if (o1 instanceof X509Data) {
                X509Data data = (X509Data) o1;
                for (Object o2 : data.getContent()) {
                    if (o2 instanceof X509Certificate) {
                        X509Certificate cert = (X509Certificate) o2;
                        if (matchingAlgorithms(cert.getPublicKey().getAlgorithm(), method.getAlgorithm())) {
                            foundCerts.add(cert);
                        }
                    }
                }
            }
        }

        if (foundCerts.size() == 0) {
            // x509 data contains no certificate
            return null;
        } else if (foundCerts.size() == 1) {
            // we got only one certificate so it is our signing certificate
            X509Certificate cert = (X509Certificate) foundCerts.get(0);

            // check if algorithm fits
            if (!matchingAlgorithms(cert.getPublicKey().getAlgorithm(), method.getAlgorithm())) {
                throw new KeySelectorException(
                        "algorithm specified by signing certificate is not supported. Certificate specified algorithm is : " + cert.getPublicKey().getAlgorithm());
            }

            return cert;
        } else {
            // we found several certificates in x509 data
            // it must be certificate chain we have at hand. sort chain and
            // return signing certificate
            ArrayList<X509Certificate> sortedCerts;
            try {
                sortedCerts = sortCerts(foundCerts);
            } catch (Exception e) {
                throw new KeySelectorException(e);
            }
            // after sorting chain the first certificate is our signing
            // certificate

            X509Certificate cert = sortedCerts.get(0);

            // check if algorithm fits
            if (!matchingAlgorithms(cert.getPublicKey().getAlgorithm(), method.getAlgorithm())) {
                throw new KeySelectorException(
                        "algorithm specified by signing certificate is not supported. Certificate specified algorithm is : " + cert.getPublicKey().getAlgorithm());
            }

            return cert;
        }
    }

    private boolean matchingAlgorithms(String keyAlg, String signAlg) {
        if ("RSA".equalsIgnoreCase(keyAlg)) {
            return SignatureMethod.RSA_SHA1.equalsIgnoreCase(signAlg);
        } else if ("DSA".equalsIgnoreCase(keyAlg)) {
            return SignatureMethod.DSA_SHA1.equalsIgnoreCase(signAlg);
        } else if ("ECDSA".equalsIgnoreCase(keyAlg)) {
            return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1".equals(signAlg);
        }
        return false;
    }

    /**
     * Method sorting the certificate with the root certificate last.
     *
     * @param icerts
     *            ICertificates
     * @return
     * @throws InvalidFormatException
     */
    private ArrayList<X509Certificate> sortCerts(List<X509Certificate> icerts)
            throws Exception {
        ArrayList<X509Certificate> retval = new ArrayList<X509Certificate>();

        // Start with finding root
        X509Certificate currentCert = null;
        for (X509Certificate icert : icerts) {

            if (icert.getIssuerDN().equals(icert.getSubjectDN())) {
                retval.add(0, icert);
                currentCert = icert;
                break;
            }
        }
        icerts.remove(currentCert);

        if (retval.size() == 0) {
            throw new Exception(
                    "Error in certificate chain, no root certificate found in chain");
        }

        int tries = 10;
        while (icerts.size() > 0 && tries > 0) {
            for (X509Certificate icert : icerts) {
                if (currentCert.getSubjectDN().equals(icert.getIssuerDN())) {
                    retval.add(0, icert);
                    currentCert = icert;
                    break;
                }
            }
            icerts.remove(currentCert);
            tries--;

            if (tries == 0) {
                throw new Exception(
                        "Error constructing a complete ca certificate chain from retrieved certificates");
            }
        }

        return retval;
    }

    @Override
    public Key getKey() {
        return this.getSigningPublicKey();
    }
}
