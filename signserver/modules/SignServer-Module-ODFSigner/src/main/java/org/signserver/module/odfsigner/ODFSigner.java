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
package org.signserver.module.odfsigner;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

//import javax.persistence.EntityManager;

import org.odftoolkit.odfdom.doc.OdfDocument;
import org.odftoolkit.odfdom.pkg.signature.DocumentSignatureManager;
import org.odftoolkit.odfdom.pkg.signature.SignatureCreationMode;
import org.signserver.common.*;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.signers.BaseSigner;

/**
 * A signer signing Open Document Format documents (ODF 1.1) .Using odfdom
 * library to parse and modify odf documents.
 * 
 * Implementation is based on analysis of output from signature operation
 * performed by Open Office 3.1. This is due to fact that there's no place in
 * ODF standard detailing document signatures.
 * 
 * Adds invisible signature to odt,ods,odp,odg.. files (created with Open Office
 * 3.1 and respecting ODF standard)
 * 
 * Patches for the ODF Toolkit library are available at:
 * https://issues.apache.org/jira/browse/ODFTOOLKIT-67
 * 
 * @author Aziz Göktepe
 * @version $Id$
 */
public class ODFSigner extends BaseSigner {
    private static final String CONTENT_TYPE = "application/octet-stream";

    
    
//    @Override
//    public void init(int workerId, WorkerConfig config,
//            WorkerContext workerContext, EntityManager workerEM) {
//        super.init(workerId, config, workerContext, workerEM);
//        
//        initIncludeCertificateLevels();
//    }
//


    @Override
    public ProcessResponse processData(ProcessRequest signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {

        ProcessResponse signResponse;

        // Check that the request contains a valid GenericSignRequest object
        // with a byte[].
        if (!(signRequest instanceof GenericSignRequest)) {
            throw new IllegalRequestException(
                    "Recieved request wasn't a expected GenericSignRequest.");
        }
        
        final ISignRequest sReq = (ISignRequest) signRequest;
        
        if (!(sReq.getRequestData() instanceof byte[])) {
            throw new IllegalRequestException(
                    "Recieved request data wasn't a expected byte[].");
        }

        byte[] data = (byte[]) sReq.getRequestData();
        final String archiveId = createArchiveId(data, (String) requestContext.get(RequestContext.TRANSACTION_ID));

        OdfDocument odfDoc;
        try {
            odfDoc = OdfDocument.loadDocument(new ByteArrayInputStream(data));
        } catch (Exception e) {
            throw new SignServerException(
                    "Data received is not in valid odf format", e);
        }

        // get signing key and construct KeyInfo to be included in signature
        PrivateKey signingPrivateKey = getCryptoToken().getPrivateKey(
                ICryptoToken.PURPOSE_SIGN);
        X509Certificate signingCertificate = (X509Certificate) getSigningCertificate();

        // create DocumentSignatureManager with OpenOffice31CompatibilityMode
        // mode.
        // we are using OpenOffice31CompatibilityMode , because user wants to
        // see signatures (and if we are in draftv1.2 mode then open office cant
        // show signatures
        // because openoffice expects signatures to be placed in
        // META-ING/documentsignatures.xml file)
        DocumentSignatureManager dsm = new DocumentSignatureManager(odfDoc,
                SignatureCreationMode.OpenOffice31CompatibilityMode);

        // sign document
        // pForceCreateNewSignatureGroup parameter is false , because we are in
        // OpenOffice31CompatibilityMode
        try {
            dsm.SignDocument(signingPrivateKey, signingCertificate, false);
        } catch (Exception e) {
            throw new SignServerException("Problem signing odf document", e);
        }

        // save document to output stream
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try {
            odfDoc.save(bout);
        } catch (Exception e) {
            throw new SignServerException(
                    "Error saving document to output stream", e);
        }
        odfDoc.close();

        // return result
        byte[] signedbytes = bout.toByteArray();
        final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, signedbytes, archiveId));

        if (signRequest instanceof GenericServletRequest) {
            signResponse = new GenericServletResponse(sReq.getRequestID(),
                    signedbytes, getSigningCertificate(), archiveId, archivables, CONTENT_TYPE);
        } else {
            signResponse = new GenericSignResponse(sReq.getRequestID(),
                    signedbytes, getSigningCertificate(), archiveId, archivables);
        }

        return signResponse;
    }
}
