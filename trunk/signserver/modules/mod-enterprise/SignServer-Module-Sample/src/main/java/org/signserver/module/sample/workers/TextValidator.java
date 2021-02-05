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
package org.signserver.module.sample.workers;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.util.CertTools;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.CertificateValidationResponse;
import org.signserver.common.data.DocumentValidationRequest;
import org.signserver.common.data.DocumentValidationResponse;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;
import org.signserver.server.validators.BaseValidator;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.Validation.Status;

/**
 * Sample validator for the "text signature" format created by TextSigner.
 * <p>
 * The worker has the following worker properties:
 * </p>
 * <ul>
 *    <li>
 *       <b>TRUSTANCHORS</b> = List of PEM encoded trusted CA certificates.
 *       (Required)
 *    </li>
 * </ul>
 * @author ...
 * @see TextSigner
 * @version $Id$
 */
public class TextValidator extends BaseValidator {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TextValidator.class);

    // Worker properties
    /** PEM encoded list of trusted certificates. */
    public static final String PROPERTY_TRUSTANCHORS = "TRUSTANCHORS";

    // Log fields
    public static final String LOG_DIGEST_VALID = "DIGEST_VALID";
    public static final String LOG_SIGNATURE_VALID = "SIGNATURE_VALID";
    public static final String LOG_CERTIFICATE_VALID = "CERTIFICATE_VALID";

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    private final Set<TrustAnchor> trustAnchors = new HashSet<>();

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Required property TRUSTANCHORS
        try {
            final String value = config.getProperty(PROPERTY_TRUSTANCHORS);
            if (value == null) {
                configErrors.add("Missing required property "
                        + PROPERTY_TRUSTANCHORS);
            } else {
                final Collection<Certificate> certs = CertTools.getCertsFromPEM(
                        new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8)));
                if (certs.isEmpty()) {
                    configErrors.add("Property " + PROPERTY_TRUSTANCHORS
                            + " must not be empty");
                } else {
                    // Add each certificate
                    for (Certificate cert : certs) {
                        if (cert instanceof X509Certificate) {
                            trustAnchors.add(new TrustAnchor(
                                    (X509Certificate) cert, null));
                        }
                    }
                }
            }
        } catch (CertificateException ex) {
            configErrors.add("Property " + PROPERTY_TRUSTANCHORS
                    + " caused error: " + ex.getMessage());
        }
    }

    @Override
    public Response processData(Request signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        try {
            if (!configErrors.isEmpty()) {
                throw new SignServerException("Worker is misconfigured");
            }
            if (!(signRequest instanceof DocumentValidationRequest)) {
                throw new IllegalRequestException("Unexpected request type");
            }
            final DocumentValidationRequest request = (DocumentValidationRequest) signRequest;

            
            // Get the data from request
            final byte[] data = request.getRequestData().getAsByteArray();
            final BufferedReader in = new BufferedReader(new InputStreamReader(
                    new ByteArrayInputStream(data), StandardCharsets.UTF_8));
            
            // First line should be header
            String line = in.readLine();
            if (line == null || !line.equals("----- BEGIN SIGNED TEXT -----")) {
                throw new IllegalRequestException(
                        "Incorrect document, expected signed text header");
            }
            
            // Read the text, use "\n" as line ending as specified by TextSigner
            final StringBuilder sb = new StringBuilder();
            while ((line = in.readLine()) != null
                    && !line.equals("----- BEGIN TEXT SIGNATURE -----")) {
                sb.append(line).append("\n");
            }
            if (line == null
                    || !line.equals("----- BEGIN TEXT SIGNATURE -----")) {
                throw new IllegalRequestException(
                        "Incorrect document, expected text signature header");
            }
            final String text = sb.toString();
            
            // Read the signature section
            final StringBuilder sb2 = new StringBuilder();
            while ((line = in.readLine()) != null
                    && !line.equals("----- END TEXT SIGNATURE -----")) {
                sb2.append(line).append("\n");
            }
            if (line == null
                    || !line.equals("----- END TEXT SIGNATURE -----")) {
                throw new IllegalRequestException(
                        "Incorrect document, expected text signature footer");
            }
            final String signatureSection = sb2.toString();
            final Properties attributes = new Properties();
            attributes.load(new StringReader(signatureSection));
            final String[] attributeNames = attributes.stringPropertyNames()
                    .toArray(new String[0]);
            // Sort as specified
            Arrays.sort(attributeNames);

            // We will charge the client regardless of the outcome of the
            // validation
            requestContext.setRequestFulfilledByWorker(true);

            // Check the digest over the text
            boolean validDigest;
            try {
                final String digestAlgorithm
                        = attributes.getProperty("contentDigestAlgorithm");
                final byte[] digest = Base64.decode(attributes.getProperty(
                        "contentDigest"));
                final MessageDigest md
                        = MessageDigest.getInstance(digestAlgorithm);
                final byte[] actualDigest = md.digest(text.getBytes(StandardCharsets.UTF_8));
                validDigest = Arrays.equals(digest, actualDigest);
            } catch (NoSuchAlgorithmException ex) {
                validDigest = false;
                LOG.info("Message digest algorithm not supported: "
                        + ex.getMessage());
            }

            // Check the signature over the attributes
            final List<Certificate> certificates
                    = CertTools.getCertsFromPEM(new ByteArrayInputStream(
                            attributes.getProperty("certificates")
                                    .getBytes(StandardCharsets.UTF_8)));
            final Certificate signerCertificate = certificates.get(0);
            boolean validSignature;
            try {
                final String signatureAlgorithm
                        = attributes.getProperty("signatureAlgorithm");
                final Signature signature
                        = Signature.getInstance(signatureAlgorithm);
                signature.initVerify(certificates.get(0));
                for (String attr : attributeNames) {
                    if (!"signature".equals(attr)) {
                        // Construct the attributes string as specified
                        // before hashing
                        final String attribute = attr + "="
                                + attributes.getProperty(attr) + "\n";
                        signature.update(attribute.getBytes(StandardCharsets.UTF_8));
                    }
                }
                final byte[] signatureBytes
                        = Base64.decode(attributes.getProperty("signature"));
                validSignature = signature.verify(signatureBytes);
            } catch (NoSuchAlgorithmException ex) {
                validSignature = false;
                LOG.info("Signature verification could not be performed: "
                        + ex.getMessage());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unsupported signature algorithm: "
                            + ex.getMessage());
                }
            } catch (InvalidKeyException ex) {
                validSignature = false;
                LOG.info("Signature verification could not be performed: "
                        + ex.getMessage());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Invalid key in signer certificate", ex);
                }
            } catch (SignatureException ex) {
                validSignature = false;
                LOG.info("Signature verification could not be performed: "
                        + ex.getMessage());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signature error", ex);
                }
            } 
            
            // Validate the signature certificate
            final Validation v
                    = validate(signerCertificate, certificates, trustAnchors);
            final boolean validCertificate = v.getStatus() == Status.VALID;
            
            // Log anything interesting from the request to the worker logger
            final String validDigestString = String.valueOf(validDigest);
            final String validSignatureString = String.valueOf(validSignature);
            LogMap.getInstance(requestContext).put(LOG_DIGEST_VALID,
                    new Loggable() {
                        @Override
                        public String toString() {
                            return validDigestString;
                        }
                    });
            LogMap.getInstance(requestContext).put(LOG_SIGNATURE_VALID,
                    new Loggable() {
                        @Override
                        public String toString() {
                            return validSignatureString;
                        }
                    });
            LogMap.getInstance(requestContext).put(LOG_CERTIFICATE_VALID,
                    new Loggable() {
                        @Override
                        public String toString() {
                            return String.valueOf(validCertificate);
                        }
                    });

            // Return the response
            return new DocumentValidationResponse(request.getRequestID(),
                    validDigest && validSignature && validCertificate,
                    new CertificateValidationResponse(v, null));
        } catch (UnsupportedEncodingException ex) {
            // This is a server-side error
            throw new SignServerException("Encoding not supported: "
                    + ex.getLocalizedMessage(), ex);
        } catch (CertificateException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unable to parse certificates from request", ex);
            }
            throw new IllegalRequestException(
                    "Unable to parse certificates attribute", ex);
        } catch (IOException ex) {
            LOG.info("Parse error: " + ex.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Parse error", ex);
            }
            throw new IllegalRequestException("Unable to parse request", ex);
        }
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        // Add our errors to the list of errors
        final LinkedList<String> errors = new LinkedList<>(
                super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }
    
    protected Validation validate(Certificate cert, List<Certificate> certChain,
            Set<TrustAnchor> trustAnchors) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException,
            CertificateException {
        // Initialize validator
        CertPathValidator validator;
        PKIXParameters params;
        CertPath certPath;
        try {
            final CertificateFactory certFactory
                    = CertificateFactory.getInstance("X509");
            certPath = certFactory.generateCertPath(certChain);
            validator = CertPathValidator.getInstance("PKIX", "BC");
            params = new PKIXParameters(trustAnchors);
            params.addCertStore(CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(certChain)));
            params.setDate(new Date());
            // XXX: A real validator should ofcourse do revocation checking.
            params.setRevocationEnabled(false);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            LOG.error("Exception on preparing parameters for validation", e);
            throw new SignServerException(e.toString(), e);
        }

        // Do the validation
        Validation result;
        try {
            validator.validate(certPath, params);
            result = new Validation(cert, certChain, Validation.Status.VALID,
                    "This certificate is valid");
        } catch (CertPathValidatorException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Certificate is not valid", e);
            }
            result = new Validation(cert, certChain,
                    Validation.Status.DONTVERIFY,
                    "Certificate validation failed");
        } catch (InvalidAlgorithmParameterException e) {
            LOG.error("Exception on validation", e);
            throw new SignServerException("Exception on validation.", e);
        }
        
        return result;
    }

}
