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

import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import javax.persistence.EntityManager;

import org.odftoolkit.odfdom.doc.OdfDocument;
import org.odftoolkit.odfdom.pkg.signature.DocumentSignatureManager;
import org.odftoolkit.odfdom.pkg.signature.SignatureCreationMode;
import org.signserver.common.*;
import org.signserver.server.IServices;
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

    private List<String> configErrors;
    
    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        configErrors = new LinkedList<>();
        
        if (hasSetIncludeCertificateLevels) {
            configErrors.add(WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS + " is not supported.");
        }
    }

    @Override
    public Response processData(Request signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {

        ProcessResponse signResponse;

        // Check that the request contains a valid GenericSignRequest object
        // with a byte[].
        if (!(signRequest instanceof SignatureRequest)) {
            throw new IllegalRequestException(
                    "Received request wasn't an expected GenericSignRequest.");
        }
        final SignatureRequest sReq = (SignatureRequest) signRequest;
        ReadableData data = sReq.getRequestData();
        final String archiveId = createArchiveId(new byte[0], (String) requestContext.get(RequestContext.TRANSACTION_ID));

        OdfDocument odfDoc;
        try {
            odfDoc = OdfDocument.loadDocument(data.getAsFile());
        } catch (Exception e) {
            throw new SignServerException(
                    "Data received is not in valid odf format", e);
        }

        X509Certificate cert = null;
        ICryptoInstance crypto = null;
        try {
            // get signing key and construct KeyInfo to be included in signature
            crypto = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, signRequest, requestContext);

            // create DocumentSignatureManager with OpenOffice31CompatibilityMode
            // mode.
            // we are using OpenOffice31CompatibilityMode , because user wants to
            // see signatures (and if we are in draftv1.2 mode then open office cant
            // show signatures
            // because openoffice expects signatures to be placed in
            // META-ING/documentsignatures.xml file)
            DocumentSignatureManager dsm = new DocumentSignatureManager(odfDoc,
                    SignatureCreationMode.OpenOffice31CompatibilityMode);
            
            cert = (X509Certificate) getSigningCertificate(crypto);

            // sign document
            // pForceCreateNewSignatureGroup parameter is false , because we are in
            // OpenOffice31CompatibilityMode
            try {
                dsm.SignDocument(crypto.getPrivateKey(), cert, false);
            } catch (Exception e) {
                throw new SignServerException("Problem signing odf document", e);
            }
        } finally {
            releaseCryptoInstance(crypto, requestContext);
        }

        // save document to output stream
        final WritableData responseData = sReq.getResponseData();
        try (OutputStream out = responseData.getAsOutputStream()) {
            odfDoc.save(out);
        } catch (Exception e) {
            throw new SignServerException(
                    "Error saving document to output stream", e);
        } finally {
            odfDoc.close();
        }

        // return result
        final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, responseData.toReadableData(), archiveId));

        // The client can be charged for the request
        requestContext.setRequestFulfilledByWorker(true);

        return new SignatureResponse(sReq.getRequestID(),
                    responseData, cert,
                    archiveId, archivables, CONTENT_TYPE);
    }

    @Override
    protected List<String> getFatalErrors(IServices services) {
        final List<String> errors = super.getFatalErrors(services);
        
        errors.addAll(configErrors);
        return errors;
    }
}
