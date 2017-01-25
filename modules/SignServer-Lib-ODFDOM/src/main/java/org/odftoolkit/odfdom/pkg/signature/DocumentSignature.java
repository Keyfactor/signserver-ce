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

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import org.odftoolkit.odfdom.pkg.manifest.OdfFileEntry;
import org.w3c.dom.Node;

/**
 * 
 * Class representing digital signature inside DigitalSignatureGroup.
 *
 * @author aziz.goktepe (aka rayback_2)
 *
 * patch originally created for SignServer project {@link http://www.signserver.org}
 */
public class DocumentSignature {

    protected Node signatureNode;
    protected DocumentSignatureGroup signatureGroup;
    protected XMLSignature signature;
    protected X509Certificate signer;
    protected PublicKey signingPublicKey;
    protected boolean isSignatureValid;
    protected List<FileEntryIdentifier> signedFileEntries;
    protected String signingTimeStringValue;
    /**
     * internal flag to keep track if signature has been verified at least once
     * note : signature can be verified using supplied certificate or using
     * certificate or key from package (if can be found)
     */
    protected boolean isVerified = false;

    public DocumentSignature(DocumentSignatureGroup pSignatureGroup, Node pSignatureNode) {
        this.signatureNode = pSignatureNode;
        this.signatureGroup = pSignatureGroup;
        try {
            verifySignatureAndFillProperties(null);
        } catch (Exception ex) {
            Logger.getLogger(DocumentSignature.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     *
     * NOTE : if any overload of Verify has not been called yet , this getter
     * will call Verify() to try to verify signature using certificate (public
     * key) found in Signature
     *
     * @return true if signature is valid (that is passed core validation)
     * @throws Exception
     */
    public boolean isSignatureValid() throws Exception {
        if (!isVerified) {
            Verify();
        }
        return this.isSignatureValid;
    }

    /**
     * gets the signing time specified from Signature.
     * NOTE : creation placement and parsing of signing time is not exactly specified in standard. This getter can return null, even if signing time is present.
     *
     * NOTE : if any overload of Verify has not been called yet , this getter
     * will call Verify() to try to verify signature using certificate (public
     * key) found in Signature
     * 
     * @return
     * @throws Exception
     */
    public String getSigningTumeStringValue() throws Exception {
        if (!isVerified) {
            Verify();
        }
        return this.signingTimeStringValue;
    }

    /**
     *
     * NOTE : if any overload of Verify has not been called yet , this getter
     * will call Verify() to try to verify signature using certificate (public
     * key) found in Signature
     * 
     * @return
     *      File Entries signed by this signature
     * @throws Exception
     */
    public List<FileEntryIdentifier> getSignedFileEntries() throws Exception {
        if (!isVerified) {
            Verify();
        }
        return this.signedFileEntries;
    }

    /**
     * gets the public key of the signer
     *
     * NOTE : if any overload of Verify has not been called yet , this getter
     * will call Verify() to try to verify signature using certificate (public
     * key) found in Signature
     * 
     * @return
     * @throws Exception
     */
    public PublicKey getSigningPublicKey() throws Exception {
        if (!isVerified) {
            Verify();
        }
        return this.signingPublicKey;
    }

    /**
     * gets the signer certificate.
     *
     * If last verification was done using call to Verify(X509Certificate)
     * method it will return passed in certificate to Verify(X509Certificate)
     * method iff certificate passed validates signature. Otherwise it will
     * return certificate found in a Signature.
     * 
     * NOTE : if any overload of Verify has not been called yet , this getter
     * will call Verify() to try to verify signature using certificate (public
     * key) found in Signature
     * 
     * @return
     *      Certificate that was used to create signature
     * @throws Exception
     */
    public X509Certificate getSigner() throws Exception {
        if (!isVerified) {
            Verify();
        }

        return this.signer;
    }

    /**
     * NOTE : if any overload of Verify has not been called yet , this getter
     * will call Verify() to try to verify signature using certificate (public
     * key) found in Signature
     *
     * @return
     * @throws Exception
     */
    public XMLSignature getSignature() throws Exception {
        if (!isVerified) {
            Verify();
        }

        return this.signature;
    }

    /**
     * signature group this signature belongs to
     * @return
     */
    public DocumentSignatureGroup getSignatureGroup() {
        return this.signatureGroup;
    }

    /**
     * xml node that defines this signature
     * @return
     */
    public Node getSignatureNode() {
        return this.signatureNode;
    }

    /**
     * method to verify signature with the certificate / public key found inside signature
     * @return
     * @throws Exception
     */
    public DocumentSignatureVerifyResult Verify() throws Exception {
        return verifySignatureAndFillProperties(null);
    }

    /**
     * method to verify signature with given certificate
     * 
     * @param pSigningCertificate
     * @return
     * @throws Exception
     */
    public DocumentSignatureVerifyResult Verify(X509Certificate pSigningCertificate) throws Exception {
        if (pSigningCertificate == null) {
            throw new NullPointerException("Certificate can not be null");
        }

        return verifySignatureAndFillProperties(pSigningCertificate);
    }

    /**
     * determines if the signer of this document signature equals to passed in document signature's signer
     * comparision is done using signing public key , and not certificate (same key can be used in more than one certificate)
     * 
     * @param pSignature
     * @return
     */
    public boolean signerEquals(DocumentSignature pSignature) throws Exception {
        return Arrays.equals(this.getSigningPublicKey().getEncoded(), pSignature.getSigningPublicKey().getEncoded());
    }

    /**
     * determines this document signatures signed same file entries as passed in document signature
     * @param pSignature
     * @return
     */
    public boolean signedFileEntriesEquals(DocumentSignature pSignature) throws Exception {
        if (this.getSignedFileEntries() == null || pSignature.getSignedFileEntries() == null) {
            return false;
        }

        if (this.getSignedFileEntries().size() != pSignature.getSignedFileEntries().size()) {
            return false;
        }

        return this.getSignedFileEntries().containsAll(pSignature.getSignedFileEntries()) &&
                pSignature.getSignedFileEntries().containsAll(this.getSignedFileEntries());
    }

    /**
     * parse signature and fill in properties
     * 
     * @param pSigningCertificate
     * @return
     * @throws Exception
     */
    private DocumentSignatureVerifyResult verifySignatureAndFillProperties(X509Certificate pSigningCertificate) throws Exception {
        //set flag indicating that verification took place
        this.isVerified = true;

        // read signature object
        XMLSignatureFactory fac = ODFSignatureHelper.CreateXMLSignatureFactory();

        // Create a DOMValidateContext
        // if validation certificate is given try to validate using given
        // certificate
        // otherwise specify a KeySelector that will search for signing key
        // inside the signature and package
        DOMValidateContext dvc;
        if (pSigningCertificate == null) {
            ODFKeySelector keySelector = new ODFKeySelector(this);
            dvc = new DOMValidateContext(keySelector, signatureNode);
        } else {
            dvc = new DOMValidateContext(pSigningCertificate.getPublicKey(),
                    this.signatureNode);
        }

        // set uri dereferencer to be our odf dereferencer with fallback to
        // default dereferencer
        dvc.setURIDereferencer(new ODFURIDereferencer(this.signatureGroup.getDocumentSignatureManager().getDocument(), fac.getURIDereferencer()));

        // Unmarshal the XMLSignature.
        XMLSignature sig = fac.unmarshalXMLSignature(dvc);
        if (sig != null) {
            this.signature = sig;
        }

        // validate signature
        this.isSignatureValid = sig.validate(dvc);

        // if signature is valid set signer certificate and key
        if (this.isSignatureValid) {
            // set signer certificate and public key (or just public key if
            // certificate could not be found but key is from package)
            // if we were passed signer certificate set it as it is, otherwise
            // get signer from keyselector
            if (pSigningCertificate == null) {
                ODFKeySelector keySelector = (ODFKeySelector) sig.getKeySelectorResult();
                this.signer = keySelector.getSigningCertificate();
                this.signingPublicKey = keySelector.getSigningPublicKey();

            } else {
                this.signer = pSigningCertificate;
                this.signingPublicKey = pSigningCertificate.getPublicKey();
            }
        }

        //get file entries that are signed by this signature
        fillSignedFileEntriesAndTimeData(this.signature);

        // return verification result
        if (this.isSignatureValid) {
            return DocumentSignatureVerifyResult.Success;
        } else {
            return DocumentSignatureVerifyResult.InvalidSignature;
        }
    }

    /**
     * finds and fills signed file entries form xmlsginature object
     * also calls tryFillSigningTimeStringValue method to try to find signaturetime 
     * @param pSignature
     * @throws Exception
     */
    private void fillSignedFileEntriesAndTimeData(XMLSignature pSignature) throws Exception {
        //NOTE: each reference inside SignedInfo assumed to be either reference to a file entry inside package or reference to local xml object (such as date and time property).
        List<String> referencedNonFileEntryXmlObjectIds = new Vector<String>();
        @SuppressWarnings("unchecked")  // XXX: If possible this should be fixed. Suppressing for now to not hide warnings from other files.
        List<Reference> signedInfoReferences = pSignature.getSignedInfo().getReferences();
        for (Reference tempRef : signedInfoReferences) {
            if (!tempRef.getURI().startsWith(Constants.XML_ELEMENT_FRAGMENT_IDENTIFIER)) {
                //it is reference to file entry inside package and not to xml element within xml 
                //add it to signed file entries list
                FileEntryIdentifier fileEntryIdent = new FileEntryIdentifier(tempRef.getURI(), OdfFileEntry.getMediaType(tempRef.getURI()));
                ensureSignedFileEntries();
                this.signedFileEntries.add(fileEntryIdent);

            } else {
                //it is xml element identifier within xml
                //add it to the list of referenced non file entry xml objects to examine later if its the date time property
                referencedNonFileEntryXmlObjectIds.add(tempRef.getURI().substring(1, tempRef.getURI().length()));
            }
        }

        // if while traversing references inside signedinfo we found something that is not file entry, there's a chance that it is a signatureproperty holding date and time of signature
        if (referencedNonFileEntryXmlObjectIds.size() > 0) {
            tryFillSigningTimeStringValue(pSignature, referencedNonFileEntryXmlObjectIds);
        }
    }

    /**
     * tries to find signature date and time by investigating all xmlobjects included in Signature
     * It searches for SignatureProperty within XmlObject that has child node with localname equals to date
     * This is not exactly the correct way to search for the signing time, but standard does not specify where and how signature time should be specified ??
     * @param pSignature
     * @param pReferencedNonFileEntryXmlObjectIds
     *          list of ids found in references list inside signedinfo, which are not references to file entry inside the package. If date and time information exists it must be in one of these elements (child nodes of)
     */
    private void tryFillSigningTimeStringValue(XMLSignature pSignature, List<String> pReferencedNonFileEntryXmlObjectIds) {
        for (Object o : pSignature.getObjects()) {
            if (o instanceof XMLObject) {
                XMLObject xmlObj = (XMLObject) o;
                // we have xmlobject see if it contains signature properties
                for (Object o2 : xmlObj.getContent()) {
                    if (o2 instanceof SignatureProperties) {
                        //we have signature properties, see if we have signature property that includes date as a child
                        SignatureProperties sigProps = (SignatureProperties) o2;
                        for (Object o3 : sigProps.getProperties()) {
                            if (o3 instanceof SignatureProperty) {
                                SignatureProperty sigProp = (SignatureProperty) o3;
                                for (Object o4 : sigProp.getContent()) {
                                    if (o4 instanceof DOMStructure) {
                                        DOMStructure domStruct = (DOMStructure) o4;
                                        if (domStruct.getNode().getLocalName().equalsIgnoreCase("date")) {
                                            //we found our date node assign field and exit
                                            //check if this property, or any of the parents is contained in the referenced non file entry xml object ids list
                                            //this check is done to ensure that this time we found is actually signed too
                                            //(reference to property or any of parents is included in signedinfo reference list)
                                            if (pReferencedNonFileEntryXmlObjectIds.contains(xmlObj.getId()) || pReferencedNonFileEntryXmlObjectIds.contains(sigProps.getId()) || pReferencedNonFileEntryXmlObjectIds.contains(sigProp.getId())) {
                                                this.signingTimeStringValue = domStruct.getNode().getTextContent();
                                                return;
                                            }

                                        }
                                    }
                                }
                            }
                        }
                    }
                }

            }
        }
    }

    /**
     * init signed file entries
     */
    private void ensureSignedFileEntries() {
        if (this.signedFileEntries == null) {
            this.signedFileEntries = new Vector<FileEntryIdentifier>();
        }
    }
}
