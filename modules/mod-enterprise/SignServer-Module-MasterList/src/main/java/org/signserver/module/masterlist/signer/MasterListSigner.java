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
package org.signserver.module.masterlist.signer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.icao.CscaMasterList;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.cesecore.util.CertTools;
import org.signserver.common.*;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.server.signers.BaseSigner;

/**
 * A Signer taking a number of certificates and produces a CSCA Master List.
 * Specification:
 * MRTD TR CSCA countersigning and Master List issuance, Version – 1.0, June 23, 2009
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class MasterListSigner extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(MasterListSigner.class);

    /** Content-type for the requested data. */
    private static final String REQUEST_CONTENT_TYPE = "application/x-pem-file";
    
    /** Content-type for the produced data. */
    private static final String RESPONSE_CONTENT_TYPE = "application/pkcs7-signature";

    // Property constants
    public static final String SIGNATUREALGORITHM_PROPERTY = "SIGNATUREALGORITHM";

    private LinkedList<String> configErrors;
    private String signatureAlgorithm;


    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Configuration errors
        configErrors = new LinkedList<>();

        // Get the signature algorithm
        signatureAlgorithm = config.getProperty(SIGNATUREALGORITHM_PROPERTY);

        if (hasSetIncludeCertificateLevels) {
            configErrors.add(WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS + " is not supported.");
        }
    }

    @Override
    public Response processData(final Request signRequest,
            final RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {

        // Check that the request contains a valid GenericSignRequest object
        // with a byte[].
        if (!(signRequest instanceof SignatureRequest)) {
            throw new IllegalRequestException(
                    "Received request wasn't an expected GenericSignRequest.");
        }
        final SignatureRequest sReq = (SignatureRequest) signRequest;

        if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }

        // TODO: In the future: check that the signer certificate follows the profile
        // TODO: In the future: check that the CSCA certificate is available

        final String archiveId = createArchiveId(new byte[0], (String) requestContext.get(RequestContext.TRANSACTION_ID));

        final ReadableData requestData = sReq.getRequestData();
        final WritableData responseData = sReq.getResponseData();
        Certificate cert = null;
        byte[] signedbytes = null;
        ICryptoInstance crypto = null;
        try {
            crypto = acquireCryptoInstance(workerId, signRequest, requestContext);
            
            // Get certificate chain and signer certificate
            List<Certificate> certs = getSigningCertificateChain(crypto);

            if (certs == null) {
                throw new IllegalArgumentException(
                        "Null certificate chain. This signer needs a certificate.");
            }
            List<X509Certificate> x509CertChain = new LinkedList<>();
            for (Certificate c : certs) {
                if (c instanceof X509Certificate) {
                    x509CertChain.add((X509Certificate) c);
                    LOG.debug("Adding to chain: "
                            + ((X509Certificate) c).getSubjectDN());
                }
            }
            cert = getSigningCertificate(crypto);
            LOG.debug("SigningCert: " + ((X509Certificate) cert).getSubjectDN());

            // Private key
            PrivateKey privKey = crypto.getPrivateKey();

            // Get the input certificates
            final List<Certificate> cscaCertificates;
            try (InputStream in = requestData.getAsInputStream()) {
                cscaCertificates = CertTools.getCertsFromPEM(in);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Input had " + cscaCertificates.size() + " certificates");
                }
            } catch (CertificateException ex) {
                throw new IllegalRequestException("Unable to parse the input certificates", ex);
            }

            // TODO: In the future: also check that the certificates are actual (CSCA)CA certificates
            try (OutputStream out = responseData.getAsOutputStream()) {
                final CMSSignedDataGenerator generator
                        = new CMSSignedDataGenerator();
                final String sigAlg = signatureAlgorithm == null ? getDefaultSignatureAlgorithm(cert.getPublicKey()) : signatureAlgorithm;
                final ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg).setProvider(crypto.getProvider()).build(privKey);

                // Get SubjectKeyIdentifier from signer certificate
                final SubjectKeyIdentifier sid;
                final Extensions extensions = new X509CertificateHolder(cert.getEncoded()).getExtensions();
                if (extensions == null) {
                    sid = null;
                } else {
                    sid = SubjectKeyIdentifier.fromExtensions(extensions);
                }
                if (sid == null) {
                    throw new SignServerException("Subject Key Identifier is mandatory in Master List Signer Certificate");
                }

                generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                         new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                         .build(contentSigner, sid.getKeyIdentifier()));

                if (certs.size() < 2) {
                    throw new SignServerException("The Master List Signer certificate MUST be included and the CSCA certificate SHOULD be included in the certificate chain");
                }
                List<Certificate> includedCertificates = certs.subList(0, 2);

                generator.addCertificates(new JcaCertStore(includedCertificates));

                final CscaMasterList cscaMasterList = createMasterList(cscaCertificates);
                final CMSTypedData content = new CMSProcessableByteArray(ICAOObjectIdentifiers.id_icao_cscaMasterList, cscaMasterList.getEncoded());

                final CMSSignedData signedData = generator.generate(content, true);
                
                // MLIST specification requires DER encoding
                final DEROutputStream derOut = new DEROutputStream(out);
                derOut.writeObject(signedData.toASN1Structure());
            } finally {
                if (crypto != null) {
                    releaseCryptoInstance(crypto, requestContext);
                }
            }

            final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST, REQUEST_CONTENT_TYPE, requestData, archiveId), 
                    new DefaultArchivable(Archivable.TYPE_RESPONSE, RESPONSE_CONTENT_TYPE, responseData.toReadableData(), archiveId));

            // Suggest new file name
            final Object fileNameOriginal = requestContext.get(RequestContext.FILENAME);
            if (fileNameOriginal instanceof String) {
                requestContext.put(RequestContext.RESPONSE_FILENAME, fileNameOriginal + ".ml");
            }

            // The client can be charged for the request
            requestContext.setRequestFulfilledByWorker(true);

            return new SignatureResponse(sReq.getRequestID(),
                        responseData, cert,
                        archiveId, archivables, RESPONSE_CONTENT_TYPE);
        } catch (OperatorCreationException ex) {
            LOG.error("Error initializing signer", ex);
            throw new SignServerException("Error initializing signer", ex);
        } catch (CertificateEncodingException ex) {
            LOG.error("Error constructing cert store", ex);
            throw new SignServerException("Error constructing cert store", ex);
        } catch (CMSException | IOException ex) {
            LOG.error("Error constructing CMS", ex);
            throw new SignServerException("Error constructing CMS", ex);
        }
    }
    
    private String getDefaultSignatureAlgorithm(final PublicKey publicKey) {
        final String result;

        if (publicKey instanceof ECPublicKey) {
            result = "SHA1withECDSA";
        }  else if (publicKey instanceof DSAPublicKey) {
            result = "SHA1withDSA";
        } else {
            result = "SHA1withRSA";
        }

        return result;
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        final LinkedList<String> errors = new LinkedList<>(super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }

    private CscaMasterList createMasterList(List<Certificate> cscaCertificates) throws CertificateEncodingException, IOException {
        // Convert certificate instances
        List<org.bouncycastle.asn1.x509.Certificate> certs = new LinkedList<>();
        for (Certificate cert : cscaCertificates) {
            final org.bouncycastle.asn1.x509.Certificate bcCert = org.bouncycastle.asn1.x509.Certificate.getInstance(new ASN1InputStream(cert.getEncoded()).readObject());
            certs.add(bcCert);
        }
        return new CscaMasterList(certs.toArray(new org.bouncycastle.asn1.x509.Certificate[0]));
    }

}
