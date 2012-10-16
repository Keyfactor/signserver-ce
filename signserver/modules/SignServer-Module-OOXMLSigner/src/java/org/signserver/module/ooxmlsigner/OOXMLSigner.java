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
package org.signserver.module.ooxmlsigner;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import javax.persistence.EntityManager;
import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.exceptions.OpenXML4JException;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackageAccess;
import org.openxml4j.opc.signature.PackageDigitalSignatureManager;
import org.openxml4j.opc.signature.RelationshipTransformProvider;
import org.signserver.common.*;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.signers.BaseSigner;

/**
 * A Signer signing Office Open XML files (ECMA 376) using the openxml4j library
 * (signature patched version. Patch applied to revision 534 to
 * https://openxml4j.svn.sourceforge.net. Patched version is available at :
 * TODO: fill in temporary address in signserver svn.).
 * 
 * Latest known version is revision 538 in the SVN repository at
 * https://openxml4j.svn.sourceforge.net/svnroot/openxml4j
 * 
 * Adds invisible singature to docx, xlsx, pptx files (created using MS Office
 * 2007, or other ECMA 376 comformant application)
 *
 * @see <a
 * href="http://www.ecma-international.org/publications/standards/Ecma-376.htm">
 * http://www.ecma-international.org/publications/standards/Ecma-376.htm</a>
 * @see <a href="http://sourceforge.net/projects/openxml4j/">
 * http://sourceforge.net/projects/openxml4j/</a>
 *
 * @author Aziz Göktepe
 * @version $Id$
 */
public class OOXMLSigner extends BaseSigner {

    private static final String CONTENT_TYPE = "application/octet-stream";

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {

        // add opc relationship transform provider
        Security.addProvider(new RelationshipTransformProvider());

        super.init(workerId, config, workerContext, workerEM);
    }

    @Override
    public ProcessResponse processData(ProcessRequest signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {

        ProcessResponse signResponse;
        ISignRequest sReq = (ISignRequest) signRequest;

        // Check that the request contains a valid GenericSignRequest object
        // with a byte[].
        if (!(signRequest instanceof GenericSignRequest)) {
            throw new IllegalRequestException(
                    "Recieved request wasn't a expected GenericSignRequest.");
        }
        if (!(sReq.getRequestData() instanceof byte[])) {
            throw new IllegalRequestException(
                    "Recieved request data wasn't a expected byte[].");
        }

        byte[] data = (byte[]) sReq.getRequestData();
        final String archiveId = createArchiveId(data, (String) requestContext.get(RequestContext.TRANSACTION_ID));

        Package docxPackage;
        try {
            docxPackage = Package.open(new ByteArrayInputStream(data),
                    PackageAccess.READ_WRITE);
        } catch (InvalidFormatException e) {
            throw new SignServerException(
                    "Data received is not in valid openxml package format", e);
        } catch (IOException e) {
            throw new SignServerException("Error opening received data", e);
        }

        // create digital signature manager object
        PackageDigitalSignatureManager dsm = new PackageDigitalSignatureManager(
                docxPackage);

        // get signing key
        PrivateKey privateKey = getCryptoToken().getPrivateKey(
                ICryptoToken.PURPOSE_SIGN);

        // get signing certificate
        X509Certificate cert = (X509Certificate) getSigningCertificate();

        // sign document
        try {
            dsm.SignDocument(privateKey, cert);
        } catch (OpenXML4JException e1) {
            throw new SignServerException("Problem signing document", e1);
        }

        // save output to package
        ByteArrayOutputStream boutFinal = new ByteArrayOutputStream();
        try {
            dsm.getContainer().save(boutFinal);
        } catch (IOException e) {
            throw new SignServerException(
                    "Error saving final output data to output", e);
        }

        byte[] signedbytes = boutFinal.toByteArray();
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
