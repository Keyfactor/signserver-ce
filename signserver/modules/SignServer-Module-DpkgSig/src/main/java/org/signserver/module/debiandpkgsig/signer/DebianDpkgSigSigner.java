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
package org.signserver.module.debiandpkgsig.signer;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.WritableData;
import org.signserver.debiandpkgsig.ar.ParsedArFile;
import org.signserver.module.openpgp.signer.BaseOpenPGPSigner;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.log4j.Logger;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.data.SignatureResponse;
import org.signserver.debiandpkgsig.ar.ArFileHeader;
import org.signserver.debiandpkgsig.utils.DebianDpkgSigUtils;
import org.signserver.module.openpgp.signer.OpenPGPUtils;
import org.signserver.server.IServices;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import static org.signserver.server.cryptotokens.ICryptoTokenV4.PARAM_INCLUDE_DUMMYCERTIFICATE;

/**
 * Signer for DebianDpkdgSig.
 *
 * @author Vinay Singh
 * @Version $Id$
 */
public class DebianDpkgSigSigner extends BaseOpenPGPSigner {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DebianDpkgSigSigner.class);
    
    // Content types    
    private static final String REQUEST_CONTENT_TYPE = "application/octet-stream";
    private static final String RESPONSE_CONTENT_TYPE = "application/octet-stream";


    @Override
    public Response processData(Request signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {

        if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }
        if (!(signRequest instanceof SignatureRequest)) {
            throw new IllegalRequestException(
                    "Received request wasn't an expected GenericSignRequest.");
        }
        final SignatureRequest sReq = (SignatureRequest) signRequest;

        // Get the data from request
        final ReadableData requestData = sReq.getRequestData();
        final WritableData responseData = sReq.getResponseData();

        try (BufferedInputStream in = new BufferedInputStream(requestData.getAsInputStream());
                BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(responseData.getAsFile()))) {

            // Parse AR file                       
            ParsedArFile ar = ParsedArFile.parseCopyAndHash(in, out, new AlgorithmIdentifier(CMSAlgorithm.MD5), new AlgorithmIdentifier(CMSAlgorithm.SHA1));
            if (LOG.isDebugEnabled()) {
                LOG.debug("\n" + ar);
            }
            
            X509Certificate signerCert = null;
            ICryptoInstance cryptoInstance = null;
            String _gpgBuilderManifest;
            ByteArrayOutputStream signedManifestOutput;
            try {
                final Map<String, Object> params = new HashMap<>();
                params.put(PARAM_INCLUDE_DUMMYCERTIFICATE, true);
                cryptoInstance = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, signRequest, params, requestContext);

                // signature value
                final JcaPGPKeyConverter conv = new JcaPGPKeyConverter();
                signerCert = (X509Certificate) getSigningCertificate(cryptoInstance);
                final PGPPublicKey pgpPublicKey = conv.getPGPPublicKey(OpenPGPUtils.getKeyAlgorithm(signerCert), signerCert.getPublicKey(), signerCert.getNotBefore());
                PGPPrivateKey pgpPrivateKey = new org.bouncycastle.openpgp.operator.jcajce.JcaPGPPrivateKey(pgpPublicKey, cryptoInstance.getPrivateKey());

                final PGPSignatureGenerator generator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpPublicKey.getAlgorithm(), digestAlgorithm).setProvider(cryptoInstance.getProvider()).setDigestProvider("BC"));
                                                
//                If UTC time zone should be used, below can be uncommented later on
//                TimeZone timeZone = TimeZone.getTimeZone("UTC");
//                Calendar calendar = Calendar.getInstance(timeZone);
                
                // create manifest file
                final Date now = new Date();
                _gpgBuilderManifest = DebianDpkgSigUtils.createManifest(pgpPublicKey.getFingerprint(), now, ar);
                final byte[] data = _gpgBuilderManifest.getBytes("ASCII");

                // Clear-text Sign the manifest file
                signedManifestOutput = new ByteArrayOutputStream();
                signClearText(pgpPrivateKey, pgpPublicKey, generator, new ByteArrayInputStream(data), signedManifestOutput, digestAlgorithm);

            } catch (PGPException ex) {
                throw new SignServerException("PGP exception", ex);
            } catch (InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter ex) {
                throw new SignServerException("Error initializing signer", ex);
            } finally {
                releaseCryptoInstance(cryptoInstance, requestContext);
            }
                 
            long currentTimeInSeconds = System.currentTimeMillis() / 1000;
            byte[] signedManifestBytes = signedManifestOutput.toByteArray();  
            
            // Create AR heaader
            ArFileHeader header = new ArFileHeader("_gpgbuilder", currentTimeInSeconds, 0, 0, 100644, signedManifestBytes.length);
            
            // Write AR header (to out)
            out.write(header.getEncoded());
            
            // Write signed manifest
            out.write(signedManifestBytes);

            // pad 2 byte aligned
            if (signedManifestBytes.length % 2 != 0) {
                out.write('\n');
            }     
                   
            // Create the archivables (request and response)
            final String archiveId = createArchiveId(new byte[0], (String) requestContext.get(RequestContext.TRANSACTION_ID));
            final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST, REQUEST_CONTENT_TYPE, requestData, archiveId), 
                    new DefaultArchivable(Archivable.TYPE_RESPONSE, RESPONSE_CONTENT_TYPE, responseData.toReadableData(), archiveId));

            // Suggest new file name
            final Object fileNameOriginal = requestContext.get(RequestContext.FILENAME);
            if (fileNameOriginal instanceof String) {
                requestContext.put(RequestContext.RESPONSE_FILENAME, fileNameOriginal);
            }

            // As everyting went well, the client can be charged for the request
            requestContext.setRequestFulfilledByWorker(true);

            // Return the response
            return new SignatureResponse(sReq.getRequestID(), responseData, signerCert, archiveId, archivables, RESPONSE_CONTENT_TYPE);

        } catch (UnsupportedEncodingException ex) {
            // This is a server-side error
            throw new SignServerException("Encoding not supported: " + ex.getLocalizedMessage(), ex);
        } catch (IOException ex) {
            throw new SignServerException("Encoding error", ex);
        } catch (OperatorCreationException ex) {
            throw new SignServerException("Algorithm error", ex);
        }
    }

    @Override
    public List<String> getFatalErrors(IServices services) {
        return super.getFatalErrors(services);
    }

    

}
