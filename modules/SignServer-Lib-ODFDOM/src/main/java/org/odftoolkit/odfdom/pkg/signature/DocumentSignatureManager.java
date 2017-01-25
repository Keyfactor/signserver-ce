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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.UUID;
import java.util.Vector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.odftoolkit.odfdom.doc.OdfDocument;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * 
 * class that manages digital signature creation, parsing and verification
 *
 * @author aziz.goktepe (aka rayback_2)
 *
 * patch originally created for SignServer project {@link http://www.signserver.org}
 */
public class DocumentSignatureManager {

    private OdfDocument document;
    List<DocumentSignatureGroup> signatureGroups;
    // private field specifying if the search for the signature files (that is DocumentSignatureGroups) has already been done
    private boolean signatureGroupsSearchDone = false;
    private SignatureCreationMode signatureCreationMode;

    /**
     * document signature manager object can be initialized in two signature creation modes : OpenOffice31CompatibilityMode or OdfV12DraftCompatibilityMode
     *
     * - if initialized in OpenOffice31CompatibilityMode then all signatures are placed in META-INF/documentsignatures.xml file entry as Open Office 3.1 wants them to be
     * - if initialized in OpenOffice31CompatibilityMode then all Sign* methods will throw exception if passed pForceCreateNewSignatureGroup parameter equal to true
     *
     * - if initialized in OdfV12DraftCompatibilityMode then signatures can be grouped in different file entries and each entry can contain multiple document signatures.
     * - if in OdfV12DraftCompatibilityMode mode then signature file entry file names are generated randomly but have "signatures" in its name and will be placed under META-INF/.
     * 
     * @param pDocument
     * @param pSignatureCreationMode
     */
    public DocumentSignatureManager(OdfDocument pDocument, SignatureCreationMode pSignatureCreationMode) {
        this.document = pDocument;
        this.signatureCreationMode = pSignatureCreationMode;
    }

    /**
     * signature creation mode Document Signature Manager is initialized with.
     * @return
     */
    public SignatureCreationMode getSignatureCreationMode() {
        return this.signatureCreationMode;
    }

    /**
     * checks if package contains any signatures. It does not verify nor parse signatures.
     * @return
     *      true if package contains any signature file (signature groups)
     */
    public boolean isSigned() {
        return getSignatureGroups() != null;
    }

    /**
     * get DocumentSignatureGroups inside the package. 
     * 
     * Note that each DocumentSignatureGroup corresponds physically to a signature file.
     * Each group can contain multiple DocumentSignatures that are related to each other in some way. 
     * @return
     *      null if there's no signature found in package
     */
    public List<DocumentSignatureGroup> getSignatureGroups() {
        if (this.signatureGroupsSearchDone) {
            //already done search for signature groups, so return found results
            return this.signatureGroups;
        } else {
            //set flag to indicate we've done search
            this.signatureGroupsSearchDone = true;

            // The format of digital signature files is specified in chapter
            for (String fileEntry : this.document.getPackage().getFileEntries()) {
                if (isSignatureFileEntry(fileEntry)) {
                    //we found signature file create DocumentSignatureGroup and att to list
                    DocumentSignatureGroup sigGroup = new DocumentSignatureGroup(this, fileEntry);

                    //ensure list initted and add to list
                    ensureSignatureGroups();
                    signatureGroups.add(sigGroup);
                }
            }

            return this.signatureGroups;
        }
    }

    /**
     * document associated with DocumentSignatureManager
     * @return
     */
    public OdfDocument getDocument() {
        return this.document;
    }

    /**
     * Adds digital signature to document. This method signs all file entries enlisted in manifest, except for directories and digital signature entries.
     *
     * If document is already signed it tries to find appropriate DocumentSignatureGroup that it can put signature into
     * , if it can't find appropriate group it will create separate document signature group (file entry) and put signature in there.
     * 
     * @param pSigningPrivateKey
     *          - signing private key
     * @param pSigningCertificate
     *          - signing certificate
     * @param pForceCreateNewSignatureGroup
     *
     *          - this parameter can only be used if DocumentSignatureManager is initialized in OdfV12DraftCompatibilityMode mode
     *          - if used in OpenOffice31CompatibilityMode Exception will be thrown
     * 
     *          - if true signature to be created is placed in separate ,newly created, signature group (signature file).
     *          - If false signature groups will be searched to find appropriate signature group for the signature. If not found it will be placed in separate, newly created, signature group (signature file)
     */
    public void SignDocument(PrivateKey pSigningPrivateKey,
            X509Certificate pSigningCertificate, boolean pForceCreateNewSignatureGroup) throws Exception {
        SignAllFileEntriesExceptDirectoryAndSignatures(pSigningPrivateKey, pSigningCertificate, pForceCreateNewSignatureGroup);
    }

    /**
     * More generic sign method to sign specific file entries in package
     *
     * If it is desired to sign all file entries in package (except for other signature file entries) use SignDocument() instead.
     * 
     * @param pFileEntriesToSign
     *      -file entries to sign
     * @param pSigningPrivateKey
     *      -signing private key
     * @param pSigningCertificate
     *      -signing certificate
     * @param pForceCreateNewSignatureGroup
     *
     *          - this parameter can only be used if DocumentSignatureManager is initialized in OdfV12DraftCompatibilityMode mode
     *          - if used in OpenOffice31CompatibilityMode Exception will be thrown
     * 
     *          - if true signature to be created is placed in separate ,newly created, signature group (signature file).
     *          - If false signature groups will be searched to find appropriate signature group for the signature. If not found it will be placed in separate, newly created, signature group (signature file)
     * @throws Exception
     */
    public void Sign(List<FileEntryIdentifier> pFileEntriesToSign, PrivateKey pSigningPrivateKey,
            X509Certificate pSigningCertificate, boolean pForceCreateNewSignatureGroup) throws Exception {
        SignInt(pFileEntriesToSign, pSigningPrivateKey, pSigningCertificate, pForceCreateNewSignatureGroup);
    }

    /**
     * init signatureGroups list
     */
    private void ensureSignatureGroups() {
        if (this.signatureGroups == null) {
            this.signatureGroups = new Vector<DocumentSignatureGroup>();
        }
    }

    /**
     * determine if given path points to signature file.
     *
     * by 2.5  Digital signatures are stored in one or more files whose relative paths begin with META-INF/.
     * The names of these files shall contain the term signatures.
     *
     * @param pFilePath
     * @return
     *      true if file is under META-INF/ and contains "signature" in a name, false otherwise
     */
    private boolean isSignatureFileEntry(String pFileEntryPath) {
        return pFileEntryPath.startsWith(Constants.PATH_TO_META_INF_DIR) && pFileEntryPath.contains(Constants.SIGNATURE_FILE_IDENTIFIER_STRING);
    }

    /**
     * signs all file entries in document except for directory entries and signature group file entries using passed in private key and certificate.
     * @param pSigningPrivateKey
     * @param pSigningCertificate
     * @param  pForceCreateNewSignatureGroup
     * 
     *          - this parameter can only be used if DocumentSignatureManager is initialized in OdfV12DraftCompatibilityMode mode
     *          - if used in OpenOffice31CompatibilityMode Exception will be thrown
     *
     * @throws Exception
     */
    private void SignAllFileEntriesExceptDirectoryAndSignatures(PrivateKey pSigningPrivateKey,
            X509Certificate pSigningCertificate, boolean pForceCreateNewSignatureGroup) throws Exception {

        //identify file entries to be signed
        List<FileEntryIdentifier> fileEntriesToSign = IdentifyPartsToBeSigned(this.getDocument());

        //call upon more generic sign
        SignInt(fileEntriesToSign, pSigningPrivateKey, pSigningCertificate, pForceCreateNewSignatureGroup);
    }

    /**
     * signs given file entries with given private key and certificate
     * 
     * @param fileEntriesToSign
     * @param pSigningPrivateKey
     * @param pSigningCertificate
     * @param pForceCreateNewSignatureGroup
     * 
     *          - this parameter can only be used if DocumentSignatureManager is initialized in OdfV12DraftCompatibilityMode mode
     *          - if used in OpenOffice31CompatibilityMode Exception will be thrown
     *
     *          - if true signature to be created is placed in separate ,newly created, signature group (signature file).
     *          - If false signature groups will be searched to find appropriate signature group for the signature. If not found it will be placed in separate, newly created, signature group (signature file)
     */
    private void SignInt(List<FileEntryIdentifier> pFileEntriesToSign, PrivateKey pSigningPrivateKey,
            X509Certificate pSigningCertificate, boolean pForceCreateNewSignatureGroup) throws Exception {

        //check if we are in OpenOffice31CompatibilityMode mode and pForceCreateNewSignatureGroup is true
        //throw exception if true, because this mode does not support multiple signature groups
        if (pForceCreateNewSignatureGroup && this.signatureCreationMode == SignatureCreationMode.OpenOffice31CompatibilityMode) {
            throw new Exception("Document Signature Manager has been initialized in OpenOffice31CompatibilityMode and this mode does not support multiple signature groups. Please call sign method with pForceCreateNewSignatureGroup parameter set to false");
        }

        // create XML signature factory (JSR-105)
        final XMLSignatureFactory fac = ODFSignatureHelper.CreateXMLSignatureFactory();

        //create signature
        Node XmlSignatureNode = CreateXmlSignature(this.getDocument(), fac, pFileEntriesToSign, pSigningCertificate, pSigningPrivateKey);

        //see if the document is signed
        if (this.isSigned()) {
            DocumentSignatureGroup groupToPutSignatureIn = null;

            //see if we explicitly wanted to place signature in separate signature group
            //search for appropriate group if not
            if (!pForceCreateNewSignatureGroup) {
                //document is signed, traverse all groups to see if our new signature will fit any of the groups
                //note : we get 0'th document signature in a group for comparision, because if there's a group there must be at least one signature in it (or exception will be thrown on group initialization).
                //also because of transitivity if first is equal, all in group must be equal
                //if we encounter group with relationship type SingleDocumentSignatureInGroup, we probe for both same signer and same file entries signed (it's single signature group, so it can relate to itself in all and any ways)
                //NOTE : if SignatureCreationMode is OpenOffice31CompatibilityMode then signature group to put signature in is fixed and path to entry is META-INF/documentsignatures.xml
                for (DocumentSignatureGroup group : this.getSignatureGroups()) {

                    //see if we are forcing open office document signature group
                    if (this.signatureCreationMode == SignatureCreationMode.OpenOffice31CompatibilityMode) {
                        if (group.getSignatureFileEntryPath().equals(Constants.PATH_TO_DOCUMENT_SIGNATURE_OPEN_OFFICE_3_1_REQUIRED)) {
                            groupToPutSignatureIn = group;
                            break;
                        } else {
                            //we are in OpenOffice31CompatibilityMode , so we are either to find META-INF/documentsugnatures.xml
                            //or create if such signature group does not exist (we are basically ignoring all other groups, as openoffice3.1 does)
                            continue;
                        }
                    }

                    if (group.getGroupRelationshipType() == SignatureGroupRelatonshipType.AllSignaturesSignedBySameKey || group.getGroupRelationshipType() == SignatureGroupRelatonshipType.SingleDocumentSignatureInGroup) {
                        //all document signatures in this group are created with same key, see if our new signature fits this group
                        boolean isSameKey = Arrays.equals(group.getDocumentSignatures().get(0).getSigningPublicKey().getEncoded(), pSigningCertificate.getPublicKey().getEncoded());
                        if (isSameKey) {
                            //we found our group for signature
                            groupToPutSignatureIn = group;
                            break;
                        }
                    } else if (group.getGroupRelationshipType() == SignatureGroupRelatonshipType.AllSignaturesSignSameFileEntries || group.getGroupRelationshipType() == SignatureGroupRelatonshipType.SingleDocumentSignatureInGroup) {
                        //all document signatures in this group are signing same file entries, see if our new signature fits this group
                        boolean isSameFileEntries = group.getDocumentSignatures().get(0).getSignedFileEntries().containsAll(pFileEntriesToSign) && pFileEntriesToSign.containsAll(group.getDocumentSignatures().get(0).getSignedFileEntries());
                        if (isSameFileEntries) {
                            //we found our group for siganture
                            groupToPutSignatureIn = group;
                            break;
                        }
                    }
                }
            }

            if (groupToPutSignatureIn != null) {
                //we have found a signature group (and thus a file entry) to put our signature in
                //open document signature group file entry and append our node under root element
                Document groupDocument = this.getDocument().getPackage().getDom(groupToPutSignatureIn.getSignatureFileEntryPath());
                Element signaturesElement = (Element) groupDocument.getFirstChild();
                Node tempNode = groupDocument.importNode(XmlSignatureNode, true);
                signaturesElement.appendChild(tempNode);
            } else {
                //we havent found a group for our signature , so we are creating new group (file entry) for our signature
                Document newSignatureGroupDoc = CreateDocumentSignatureGroupDocument(XmlSignatureNode);
                //add our file entry to package
                //last parameter is false, since there are already signatures is this package, there must already be entry in manifest.xml for META-INF/
                AddDocumentSignaturePart(this.getDocument(), newSignatureGroupDoc, false);
            }

        } else {
            //document is not signed, we are creating first signature in document
            Document newSignatureGroupDoc = CreateDocumentSignatureGroupDocument(XmlSignatureNode);
            //add our file entry to package (and add if not exists entry in manifest for META-INF/ dir)
            AddDocumentSignaturePart(this.getDocument(), newSignatureGroupDoc, true);
        }
    }

    /**
     * creates DocumentSignatureGroup xml Document to hold signature passed in
     * @param pXmlSignatureNode
     * @return
     * @throws ParserConfigurationException
     */
    private Document CreateDocumentSignatureGroupDocument(Node pXmlSignatureNode) throws ParserConfigurationException {
        // create document to hold signature document
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        // create document signature Document
        org.w3c.dom.Document documentSignaturesDoc = dbf.newDocumentBuilder().newDocument();

        Element documentSignaturesElement = documentSignaturesDoc.createElementNS(Constants.NMS_URI_DOCUMENT_SIGNATURES,
                Constants.NODE_NAME_DOCUMENT_SIGNATURES);

        // import signatureDoc into the newly documentsignatures doc
        Node tempNode = documentSignaturesDoc.importNode(pXmlSignatureNode, true);
        documentSignaturesElement.appendChild(tempNode);

        documentSignaturesDoc.appendChild(documentSignaturesElement);

        return documentSignaturesDoc;
    }

    /**
     * Adds document signature file entry to package. Also adds required file entries
     * into the manifest file.
     *
     * @param pOdfDoc
     * @param pDocumentSignaturePartContent
     * @param pAddMetaInfDirInManifest
     *          if true adds reference to META-INF/ directory in manifest.xml file (if does not already exist).
     * @throws Exception
     */
    public void AddDocumentSignaturePart(OdfDocument pOdfDoc,
            Document pDocumentSignatureGroupDocument, boolean pAddMetaInfDirInManifest) throws Exception {

        if (pAddMetaInfDirInManifest) {
            // add file entry to manifest to point to manifest directory
            addEntryToManifest(pOdfDoc, Constants.PATH_TO_META_INF_DIR, "");
        }

        String pathToSignatureFileEntry = null;

        if (this.signatureCreationMode == SignatureCreationMode.OpenOffice31CompatibilityMode) {
            pathToSignatureFileEntry = Constants.PATH_TO_DOCUMENT_SIGNATURE_OPEN_OFFICE_3_1_REQUIRED;
        } else {
            //generate filename postfix for signature file entry
            UUID uuid = UUID.randomUUID();
            pathToSignatureFileEntry = Constants.PATH_TO_DOCUMENT_SIGNATURE_PREFIX + uuid.toString().replace("-", "") + ".xml";
        }

        // add file entry to package
        pOdfDoc.getPackage().insert(pDocumentSignatureGroupDocument,
                pathToSignatureFileEntry, null);

        // add file entry to manifest to point to newly added part
        // observed from openoffice3.1: media-type is empty string (why not txt/xml ?)
        addEntryToManifest(pOdfDoc, pathToSignatureFileEntry, "");


    }

    /**
     * method  to create XMLSignature . Signature will sign file entries specified by pFileEntriesToSign using private key and certificate specified
     * 
     * @param pOdfDocument
     *          - ODF Document that is to be signed
     * @param fac
     *          - XMLSignatureFactory object (to avoid duplicate initializaton)
     * @param pFileEntriesToSign
     *          - file entries to be signed by this signature
     * @param pSigningCertificate
     *          - signing private key's certificate.
     * @param pPrivateKey
     *          - signing private key
     * @return
     *      Signature node
     * 
     * @throws MarshalException
     * @throws NoSuchAlgorithmException
     * @throws XMLSignatureException
     * @throws InvalidAlgorithmParameterException
     * @throws ParserConfigurationException
     * @throws KeyException
     */
    private Node CreateXmlSignature(OdfDocument pOdfDocument, XMLSignatureFactory fac, List<FileEntryIdentifier> pFileEntriesToSign, X509Certificate pSigningCertificate, PrivateKey pSigningPrivateKey) throws MarshalException, NoSuchAlgorithmException, XMLSignatureException, InvalidAlgorithmParameterException, ParserConfigurationException, KeyException {
        // create document to hold signature document
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        org.w3c.dom.Document signatureDoc = dbf.newDocumentBuilder().newDocument();

        // c14n transform to be used in all references that refer to media-type
        // text/xml
        CanonicalizationMethod cm = fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);
        // list of references to be included in manifest
        List<Reference> signedInfoReferences = new Vector<Reference>();
        // add references to parts
        // if part's media type is text/xml add c14n transform, otherwise not
        // (for example pictures will be digested as raw octet stream)
        for (FileEntryIdentifier tempPart : pFileEntriesToSign) {
            List<Transform> transforms = null;
            if (tempPart.getMediaType().equals(Constants.MEDIA_TYPE_TEXT_XML)) {
                transforms = new Vector<Transform>();
                transforms.add(cm);
            }
            Reference refPart = fac.newReference(tempPart.getFullPath(), fac.newDigestMethod(DigestMethod.SHA1, null), transforms, null, null);
            // add to signedInfo references
            signedInfoReferences.add(refPart);
        }

        //generate Ids for Signature and SignatureProperty holding datetime
        UUID uuid = UUID.randomUUID();
        String signatureId = Constants.ID_SIGNATURE_PREFIX + uuid.toString();
        String signaturePropertyDateTimeId = Constants.ID_SIGNATURE_PROPERTY_DATETIME_PREFIX + uuid.toString();

        // create Signature Properties
        SignatureProperties signatureProperties = createSignatureProperties(fac, signatureDoc, signatureId, signaturePropertyDateTimeId);

        // add object to hold signatureproperties
        List<XMLStructure> signaturePropertiesObjectContent = new ArrayList<XMLStructure>();
        signaturePropertiesObjectContent.add(signatureProperties);
        XMLObject signaturePropertiesObject = fac.newXMLObject(signaturePropertiesObjectContent, null, null, null);
        List<XMLObject> signatureObjects = new Vector<XMLObject>();
        signatureObjects.add(signaturePropertiesObject);
        // create signature properties reference
        Reference refSignatureProperties = fac.newReference("#" + signaturePropertyDateTimeId, fac.newDigestMethod(DigestMethod.SHA1, null), null, null, null);
        signedInfoReferences.add(refSignatureProperties);
        // construct signedinfo
        SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null), fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), signedInfoReferences);

        //construct keyInfo
        KeyInfo ki = null;
        KeyInfoFactory kif = fac.getKeyInfoFactory();

        KeyValue kv;
        kv = kif.newKeyValue(pSigningCertificate.getPublicKey());

        X509Data x509d = kif.newX509Data(Collections.singletonList(pSigningCertificate));

        List<XMLStructure> keyInfoContents = new Vector<XMLStructure>();
        keyInfoContents.add(kv);
        keyInfoContents.add(x509d);
        ki = kif.newKeyInfo(keyInfoContents);

        XMLSignature signature = fac.newXMLSignature(si, ki, signatureObjects, signatureId, null);
        DOMSignContext dsc = new DOMSignContext(pSigningPrivateKey, signatureDoc);

        // set ODF URI dereferencer as default URI dereferencer with fallback to
        // original dereferencer
        dsc.setURIDereferencer(new ODFURIDereferencer(pOdfDocument, fac.getURIDereferencer()));

        // actually sign
        signature.sign(dsc);

        //return signature node
        return signatureDoc.getFirstChild();
    }

    /**
     * this method identifies which file entries should be
     * included in signature creation for document signature. We include every file entry that is not a
     * directory or a signature file (that is we dont sign other signature files)
     *
     * Each included file identifier's reference digest is calculated by looking at the media-type
     * of the part.if media-type says it is text/xml then x14n transform is
     * applied. Otherwise it is digested as octet-data
     *
     * @param pOdfDoc
     *            - OdfTextDocument to be signed
     * @return
     * @throws Exception
     */
    private List<FileEntryIdentifier> IdentifyPartsToBeSigned(
            OdfDocument pOdfDoc) throws Exception {

        List<FileEntryIdentifier> partsToSign = new Vector<FileEntryIdentifier>();

        // trying to identify file entries to sign
        // for document signature we sign all file entries except
        // directories (that is the full-path attribute not ending with /) and signatures (that is isSignatureFileEntry() returns true)
        Document doc = pOdfDoc.getPackage().getDom(
                Constants.PATH_TO_MANIFEST_XML);

        // 1st dimension is enough do not recurse
        NodeList childNodes = doc.getFirstChild().getChildNodes();
        for (int i = 0, size = childNodes.getLength(); i < size; i++) {
            Node tempNode = childNodes.item(i);

            NamedNodeMap attrNodeList = tempNode.getAttributes();
            if (attrNodeList != null) {
                Node fullPathAttrNode = attrNodeList.getNamedItemNS(
                        Constants.NMS_URI_MANIFEST,
                        Constants.ATTR_NAME_FULL_PATH);
                Node mediaTypeAttrNode = attrNodeList.getNamedItemNS(
                        Constants.NMS_URI_MANIFEST,
                        Constants.ATTR_NAME_MEDIA_TYPE);
                if (fullPathAttrNode != null) {
                    if (!fullPathAttrNode.getNodeValue().endsWith("/") && !isSignatureFileEntry(fullPathAttrNode.getNodeValue())) {
                        FileEntryIdentifier tempPart = new FileEntryIdentifier(
                                fullPathAttrNode.getNodeValue(),
                                mediaTypeAttrNode.getNodeValue());
                        partsToSign.add(tempPart);
                    }
                }
            }
        }

        return partsToSign;
    }

    /**
     * Adds file entry to manifest for the specified part with specified
     * media-type
     *
     * if file entry already exists (same path and media type) it is not added
     *
     * @param pOdfDoc
     *            - Odf document to be signed
     * @param pPartPath
     *            - full path of file entry
     * @param pMediaType
     *            - media type of file entry to add
     * @throws Exception
     */
    private void addEntryToManifest(OdfDocument pOdfDoc,
            String pPartPath, String pMediaType) throws Exception {

        Document doc = pOdfDoc.getPackage().getDom(
                Constants.PATH_TO_MANIFEST_XML);
        Node firstChild = doc.getFirstChild();

        NodeList childNodes = firstChild.getChildNodes();
        for (int i = 0, size = childNodes.getLength(); i < size; i++) {
            Node tempNode = childNodes.item(i);
            NamedNodeMap attrNodeList = tempNode.getAttributes();
            if (attrNodeList != null) {
                Node fullPathAttrNode = attrNodeList.getNamedItemNS(
                        Constants.NMS_URI_MANIFEST,
                        Constants.ATTR_NAME_FULL_PATH);
                Node mediaTypeAttrNode = attrNodeList.getNamedItemNS(
                        Constants.NMS_URI_MANIFEST,
                        Constants.ATTR_NAME_MEDIA_TYPE);
                if (fullPathAttrNode != null) {
                    if (fullPathAttrNode.getNodeValue().equalsIgnoreCase(
                            pPartPath) && mediaTypeAttrNode.getNodeValue().equalsIgnoreCase(pMediaType)) {
                        return;
                    }
                }
            }
        }

        Element newElement = doc.createElementNS(Constants.NMS_URI_MANIFEST,
                Constants.NODE_NAME_FILE_ENTRY);
        newElement.setPrefix(Constants.NMS_PREFIX_MANIFEST);
        newElement.setAttributeNS(Constants.NMS_URI_MANIFEST,
                Constants.ATTR_NAME_MEDIA_TYPE, pMediaType);
        newElement.setAttributeNS(Constants.NMS_URI_MANIFEST,
                Constants.ATTR_NAME_FULL_PATH, pPartPath);

        firstChild.appendChild(newElement);
    }

    /**
     * TODO: BETTER HANDLING NEEDED
     *
     * creates signature properties to be included in signature document.
     * signature properties element has single signature property element
     * holding date and time of signature
     *
     * @param fac
     *            - XMLSignatureFactory to be used (not to create again and
     *            again)
     * @param pSignatureDoc
     *            - document containing signature data (constructed so far)
     * @param pSignatureElementId
     *            - Id of the Signature element
     * @param pSignatureDateTimePropertyElementId
     *            - Id of the SignatureDateTime SignatureProperty to be constructed
     * @return
     */
    private SignatureProperties createSignatureProperties(
            XMLSignatureFactory fac, Document pSignatureDoc, String pSignatureElementId, String pSignatureDateTimePropertyElementId) {

        Calendar now = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        Date signingTime = now.getTime();

        String signatureDateTimeFormatString = "yyyy-MM-dd'T'HH:mm:ss";
        SimpleDateFormat sdf = new SimpleDateFormat(
                signatureDateTimeFormatString);

        String dateFriendly = sdf.format(signingTime);

        // signature time
        Element signDateTimeElement = pSignatureDoc.createElementNS(
                Constants.NMS_URI_SIGNATURE_PROPERTY_DATETIME_DATE_ELEM,
                Constants.NODE_NAME_SIGNATURE_PROPERTY_DATETIME_DATE);

        signDateTimeElement.setPrefix(Constants.NMS_PREFIX_SIGNATURE_PROPERTY_DATETIME_DATE_ELEM);

        // explicitly add namespace so it is not omitted during c18n
        signDateTimeElement.setAttributeNS(
                "http://www.w3.org/2000/xmlns/",
                "xmlns:" + Constants.NMS_PREFIX_SIGNATURE_PROPERTY_DATETIME_DATE_ELEM,
                Constants.NMS_URI_SIGNATURE_PROPERTY_DATETIME_DATE_ELEM);

        signDateTimeElement.appendChild(pSignatureDoc.createTextNode(dateFriendly));

        List<DOMStructure> signaturePropertiesElems = new ArrayList<DOMStructure>();
        signaturePropertiesElems.add(new DOMStructure(signDateTimeElement));

        SignatureProperty signatureProperty = fac.newSignatureProperty(
                signaturePropertiesElems, "#" + pSignatureElementId,
                pSignatureDateTimePropertyElementId);

        SignatureProperties signatureProperties = fac.newSignatureProperties(
                Collections.singletonList(signatureProperty), null);

        return signatureProperties;
    }
}
