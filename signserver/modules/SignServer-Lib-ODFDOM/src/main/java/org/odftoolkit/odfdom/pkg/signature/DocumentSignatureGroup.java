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

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Vector;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * This class holds group of DocumentSignature objects.
 * Physically this object corresponds to a digital signature file.
 * 
 * By OpenDocument v1.2 draft ;
 * Digital signatures are stored in one or more files whose relative paths begin with META-INF/.
 * The names of these files shall contain the term signatures.
 *
 * The format of the digital signature files is defined by the OpenDocument digital signature schema Relax-NG [RNG] schema.
 *
 * This file should contain one <dsig:document-signatures> root element.
 *
 * The <dsig:document-signatures> root element serves as a container for an arbitrary number of <xmldsig:Signature> elements.
 * If the <dsig:document-signatures> element contains multiple <xmldsig:Signature> elements,
 * then there should be a relation between the digital signatures they define,
 * for instance, they may all apply to the same set of files.
 *
 * <xmldsig:Signature> element is represented by DocumentSignature class
 *
 * Restrictions ;
 *
 * The <dsig:document-signatures> element is a root element.
 * The <dsig:document-signatures> element has no attributes.
 * The <dsig:document-signatures> element has the following child element: <xmldsig:Signature>
 * 
 * @author aziz.goktepe (aka rayback_2)
 *
 * patch originally created for SignServer project {@link http://www.signserver.org}
 */
public class DocumentSignatureGroup {

    private DocumentSignatureManager documentSignatureManager;
    private String signatureFileEntryPath;
    private List<DocumentSignature> documentSignatures;
    //specifies how are all DocumentSignatures related to each other
    private SignatureGroupRelatonshipType relationshipType;
    // private field specifying if relationship type was searched for
    private boolean relationshipTypeSearchDone = false;
    // private field specifying if file has been parsed to get document signatures out of it
    private boolean signatureParsingDone = false;

    public DocumentSignatureGroup(DocumentSignatureManager pDocumentSignatureManager, String pSignatureFileEntryPath) {
        this.documentSignatureManager = pDocumentSignatureManager;
        this.signatureFileEntryPath = pSignatureFileEntryPath;
        //TODO : check if signature file is well formed
    }

    /**
     * Path to digital signature file entry which this object refers to
     * @return
     */
    public String getSignatureFileEntryPath() {
        return this.signatureFileEntryPath;
    }

    /**
     * DocumentSignatureManager object associated with this Document Signature Group.
     * @return
     */
    public DocumentSignatureManager getDocumentSignatureManager() {
        return this.documentSignatureManager;
    }

    /**
     *
     * @return
     *     document signatures contained in this document signature group (signature file)
     */
    public List<DocumentSignature> getDocumentSignatures() throws Exception {
        if (this.signatureParsingDone) {
            //already parsed file to get document signatures so return results
            return this.documentSignatures;
        } else {
            //set flag to indicate we've done parsing
            this.signatureParsingDone = true;

            //parse file to find all Document signatures
            Document doc = this.documentSignatureManager.getDocument().getPackage().getDom(this.signatureFileEntryPath);
            Node documentSignaturesNode = doc.getFirstChild();

            //see if root element is <dsig:document-signatures>, throw exception if not by 4.2 of draft (The <dsig:document-signatures> element is a root element.)
            if (!documentSignaturesNode.getLocalName().equalsIgnoreCase(Constants.NODE_NAME_DOCUMENT_SIGNATURES)) {
                throw new Exception("Digital Signature file not well formed. Root element of signature file should be <dsig:document-signatures>");
            }

            //see if root element has any attributes, throw exception if does by 4.2 of draft (The <dsig:document-signatures> element has no attributes.)
            //NOTE : we skip xmlns attributes, and throw exception if any other attribute is found (draft does not mention that ??)
            NamedNodeMap attrNodeList = documentSignaturesNode.getAttributes();
            if (attrNodeList != null && attrNodeList.getLength() > 0) {
                for (int i = 0; i < attrNodeList.getLength(); i++) {
                    Attr attr = (Attr) attrNodeList.item(i);
                    if (!attr.getName().trim().equalsIgnoreCase("xmlns")) {
                        throw new Exception("Digital Signature file not well formed. Root element of signature file should contain no attributes.");
                    }
                }
            }

            NodeList childNodes = documentSignaturesNode.getChildNodes();

            // see if there's any signature defined in file, throw exception if not.
            // Its digital signature schema :
            //<element name="dsig:document-signatures">
            // <oneOrMore>
            //		<ref name="xmldsig-signature"/>
            //	</oneOrMore>
            //</element>
            if (childNodes == null || childNodes.getLength() == 0) {
                throw new Exception("Digital Signature file not well formed. At least one <xmldsig:Signature> element must be present in digital signature file");
            }

            for (int i = 0, size = childNodes.getLength(); i < size; i++) {
                Node tempNode = childNodes.item(i);
                //see if its Signature element , throw exception if not by 4.2 and signature schema definition
                if (!tempNode.getLocalName().equalsIgnoreCase("Signature")) {
                    throw new Exception("Digital Signature file not well formed. Some element other than <xmldsig:Signature> was found");
                }

                //ok so we have legal signature element at hand , add it to documentsignatures list
                ensureDocumentSignatures();
                DocumentSignature dsig = new DocumentSignature(this, tempNode);
                this.documentSignatures.add(dsig);
            }

            return this.documentSignatures;
        }
    }

    /**
     * tries to find how do signatures in group relate to each other.
     * search is done to see if all signatures are signed by same signer, or all signatures sign same file entries.
     *
     * Order of priority is : AllSignaturesSignedBySameKey,AllSignaturesSignSameFileEntries.
     * i.e. : if all signatures are signed by same signer and all signetures sign same document, relationship type will be AllSignaturesSignedBySameKey.
     *
     * NOTE : it will call Verify() on each DocumentSignature object, if Verify() or Verify(X509Certificate) has not been called previously.
     * 
     * @return
     *      Relationship type if found, Unknown otherwise. Will return SingleDocumentSignatureInGroup for signature group that contain single document signature entry.
     * @throws Exception
     */
    public SignatureGroupRelatonshipType getGroupRelationshipType() throws Exception {
        if (this.relationshipTypeSearchDone) {
            //relationship has been searched for , return result
            return relationshipType;
        } else {
            //set flag that search is done
            this.relationshipTypeSearchDone = true;

            //if there's single signature in group set relationship type accordingly (single signature can relate in all ways to itself, so it deserves to be handled separately)
            if (this.getDocumentSignatures().size() == 1) {
                this.relationshipType = SignatureGroupRelatonshipType.SingleDocumentSignatureInGroup;
            } else {
                //ok we got multiple document signatures, so how do they relate 
                //(no really, how do they relate in terms of standard , there's no specific relationship type specified, just broad definition of relation)

                //temp var to see if we found our relationship type
                boolean relationshipTypeFound = false;

                //compare signers
                //take first document signature and compare to all rest, because of transitivity, if first is equal to all, then all equal
                boolean allSignaturesSignedBySameKey = true;
                for (int i = 1; i < this.getDocumentSignatures().size(); i++) {
                    if (!this.getDocumentSignatures().get(0).signerEquals(this.getDocumentSignatures().get(i))) {
                        //we found at least one that is not signed by same key
                        allSignaturesSignedBySameKey = false;
                        break;
                    }
                }

                if (allSignaturesSignedBySameKey) {
                    //all signatures are signed by same key, set relationship type accordingly
                    relationshipTypeFound = true;
                    this.relationshipType = SignatureGroupRelatonshipType.AllSignaturesSignedBySameKey;
                }

                if (!relationshipTypeFound) {
                    //we haven't found relationship type so far, try comparing signed file entries
                    //again take first document signature and compare to all rest, transitivity will make sure they are all equal if first equals to all
                    boolean allSignaturesSignSameFileEntries = true;
                    for (int i = 1; i < this.getDocumentSignatures().size(); i++) {
                        if (!this.getDocumentSignatures().get(0).signedFileEntriesEquals(this.getDocumentSignatures().get(i))) {
                            //we found at least one signature that does not sign same file entries
                            allSignaturesSignSameFileEntries = false;
                            break;
                        }
                    }

                    if (allSignaturesSignSameFileEntries) {
                        //all signatures sign same file entries
                        relationshipTypeFound = true;
                        this.relationshipType = SignatureGroupRelatonshipType.AllSignaturesSignSameFileEntries;
                    }
                }

                //see if we found relationship type, set relationship type to Unknown if not
                if (!relationshipTypeFound) {
                    this.relationshipType = SignatureGroupRelatonshipType.Unknown;
                }
            }

            //return relationship type
            return this.relationshipType;
        }
    }

    /**
     * verifies all signatures in signature group. Stops verification when encounters first signature that does not verify correctly.
     * @return
     *      success if all signatures verify OK, InvalidSignature if at least one signature does not verify.
     */
    public DocumentSignatureVerifyResult Verify() throws Exception {
        for (DocumentSignature sig : this.getDocumentSignatures()) {
            DocumentSignatureVerifyResult result = sig.Verify();
            if (result != DocumentSignatureVerifyResult.Success) {
                return result;
            }
        }

        return DocumentSignatureVerifyResult.Success;
    }

    /**
     * verifies all signatures in signature group using passed in certificate.
     * Stops verification when encounters first signature that does not verify correctly.
     * 
     * @return
     *      success if all signatures verify OK, InvalidSignature if at least one signature does not verify.
     */
    public DocumentSignatureVerifyResult Verify(X509Certificate pSigningCertificate) throws Exception {
        for (DocumentSignature sig : this.getDocumentSignatures()) {
            DocumentSignatureVerifyResult result = sig.Verify(pSigningCertificate);
            if (result != DocumentSignatureVerifyResult.Success) {
                return result;
            }
        }

        return DocumentSignatureVerifyResult.Success;
    }

    /**
     * init documentsignatures list
     */
    private void ensureDocumentSignatures() {
        if (this.documentSignatures == null) {
            this.documentSignatures = new Vector<DocumentSignature>();
        }
    }
}
