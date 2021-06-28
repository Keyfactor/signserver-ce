/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.ades.signer;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import javax.persistence.EntityManager;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;
import static org.signserver.module.ades.AdESSignatureLevel.TIMESTAMPING_REQUIRED;

import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.module.ades.*;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.WritableData;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import static org.signserver.module.ades.AdESSignatureLevel.REVOCATION_REQUIRED;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.server.media.MediaType;
import org.signserver.server.signers.BaseSigner;

/**
 * AdES (eIDAS Advanced Electronic Signature) signer.
 *
 * Currently supports: PAdES (PDF) and XAdES (XML) signing.
 *
 * @author Makus Kilås
 * @version $Id$
 */
public class AdESSigner extends BaseSigner {

    private static final Logger LOG = Logger.getLogger(AdESSigner.class);

    // Worker properties
    public static final String PROPERTY_SIGNATUREALGORITHM
            = "SIGNATUREALGORITHM";

    /** Worker property for signature level. */
    public static final String PROPERTY_SIGNATURE_LEVEL = "SIGNATURE_LEVEL";

    /** Worker property for digest algorithm. */
    public static final String PROPERTY_DIGESTALGORITHM = "DIGESTALGORITHM";

    /** Worker property for TSA worker. */
    public static final String TSA_WORKER = "TSA_WORKER";

    /** Worker property for TSA URL. */
    public static final String TSA_URL = "TSA_URL";

    /** Worker property for TSA username. */
    public static final String TSA_USERNAME = "TSA_USERNAME";

    /** Worker property for TSA password. */
    public static final String TSA_PASSWORD = "TSA_PASSWORD";

    /** Worker property the TSA digest algorithm. */
    public static final String TSA_DIGESTALGORITHM = "TSA_DIGESTALGORITHM";

    /** Worker property for adding content timestamp. */
    public static final String ADD_CONTENT_TIMESTAMP = "ADD_CONTENT_TIMESTAMP";

    /** Worker property for adding additional trusted certs (trust anchors). */
    public static final String TRUSTANCHORS = "TRUSTANCHORS";

    /**
     * Worker property for XAdES signature packaging.
     */
    public static final String PROPERTY_SIGNATURE_PACKAGING = "SIGNATURE_PACKAGING";

    /**
     * Worker property for PAdES extra signature space.
     */
    public static final String PROPERTY_EXTRA_SIGNATURE_SPACE = "EXTRA_SIGNATURE_SPACE";

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    private AdESSignatureFormat signatureFormat;
    private AdESSignatureLevel signatureLevel;
    private SignaturePackaging signaturePackaging;
    private DigestAlgorithm digestAlgorithm;
    private SignatureAlgorithm signatureAlgorithm;
    private String tsaURL;
    private String tsaWorker;
    private String tsaUsername;
    private String tsaPassword;
    private DigestAlgorithm tsaDigestAlgorithm;
    private boolean addContentTimestamp;
    private List<CertificateToken> trustedCertificates;
    private int extraSignatureSpace;

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Redefine the XML factories to use the ones with the JRE instead of
        // it being the first on the classpath as for instance the Xerces in
        // JBoss does not work with the default way DSS creates secure factories
        LOG.info("Previous transformer property: " + System.getProperty("javax.xml.transform.TransformerFactory"));
        System.setProperty("javax.xml.transform.TransformerFactory", "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl");
        LOG.info("Current  transformer property: " + System.getProperty("javax.xml.transform.TransformerFactory"));
        LOG.info("Previous schema property:      " + System.getProperty("javax.xml.validation.SchemaFactory:http://www.w3.org/2001/XMLSchema"));
        System.setProperty("javax.xml.validation.SchemaFactory:http://www.w3.org/2001/XMLSchema", "com.sun.org.apache.xerces.internal.jaxp.validation.XMLSchemaFactory");
        LOG.info("Current  schema property:      " + System.getProperty("javax.xml.validation.SchemaFactory:http://www.w3.org/2001/XMLSchema"));

        // Optional property SIGNATUREALGORITHM
        final String signatureAlgorithmString =
                config.getProperty(PROPERTY_SIGNATUREALGORITHM);
        if (StringUtils.isNotBlank(signatureAlgorithmString)) {
            try {
                signatureAlgorithm =
                    SignatureAlgorithm.forJAVA(signatureAlgorithmString);
            } catch (IllegalArgumentException e) {
                configErrors.add("Unknown signature algorithm: " +
                                 signatureAlgorithmString);
            }
        }

        // Read properties
        String signatureLevelString =
                config.getProperty(PROPERTY_SIGNATURE_LEVEL);

        if (signatureLevelString == null) {
            configErrors.add("Missing required property " +
                             PROPERTY_SIGNATURE_LEVEL);
        } else {
            signatureLevelString = signatureLevelString.trim();

            try {
                signatureLevel =
                        AdESSignatureLevel.valueByName(signatureLevelString);
            } catch (IllegalArgumentException e) {
                final StringBuilder sb = new StringBuilder();

                sb.append("Unknown signature level: ");
                sb.append(signatureLevelString);
                sb.append(", supported values: ");
                sb.append(StringUtils.join(AdESSignatureLevel.values(), ","));

                configErrors.add(sb.toString());
            }
        }

        final String digestAlgorithmString =
                config.getProperty(PROPERTY_DIGESTALGORITHM);

        if (StringUtils.isNotEmpty(digestAlgorithmString)) {
            try {
                digestAlgorithm =
                        DigestAlgorithm.valueOf(digestAlgorithmString.trim());
            } catch (IllegalArgumentException e) {
                configErrors.add("Unknown digest algorithm: " +
                                 digestAlgorithmString);
            }
        }

        String signatureFormatString = config.getProperty(AdESWorkerConfigProperty.SIGNATURE_FORMAT);
        if (signatureFormatString == null) {
            configErrors.add("Missing required property " +
                             AdESWorkerConfigProperty.SIGNATURE_FORMAT);
        } else {
            signatureFormatString = signatureFormatString.trim();

            try {
                signatureFormat =
                        AdESSignatureFormat.valueOf(signatureFormatString);
            } catch (IllegalArgumentException ex) {
                final StringBuilder sb = new StringBuilder();

                sb.append("Unknown signature format: ");
                sb.append(signatureFormatString);
                sb.append(", supported values: ");
                sb.append(StringUtils.join(AdESSignatureFormat.values(), ","));

                configErrors.add(sb.toString());
            }
        }
        if (signatureFormat != AdESSignatureFormat.PAdES && config.getProperty(PROPERTY_EXTRA_SIGNATURE_SPACE) != null) {
            configErrors.add(PROPERTY_EXTRA_SIGNATURE_SPACE + " property is not supported with " + signatureFormat);
        }

        if (signatureFormat == AdESSignatureFormat.XAdES) {
            String property = null;
            try {
                property = config.getProperty(PROPERTY_SIGNATURE_PACKAGING);
                if (property == null || property.isEmpty()) {
                    configErrors.add("Missing required property " +
                            PROPERTY_SIGNATURE_PACKAGING);
                } else {
                    //passed not empty value
                    signaturePackaging = SignaturePackaging.valueOf(property);
                }
            } catch (IllegalArgumentException e) {
                configErrors.add("Unknown signature packaging: " +
                        property);
            }
        } else if (signatureFormat == AdESSignatureFormat.PAdES) {
            String property = null;
            property = config.getProperty(PROPERTY_EXTRA_SIGNATURE_SPACE);
            if (property != null) {
                try {
                    extraSignatureSpace = Integer.parseInt(property);
                } catch (NumberFormatException e) {
                    configErrors.add(property + " is not a valid number");
                }
            }
            if (config.getProperty(PROPERTY_SIGNATURE_PACKAGING) != null) {
                configErrors.add(PROPERTY_SIGNATURE_PACKAGING + " property is not supported with PAdES");
            }
        }

        if (signatureAlgorithm != null && digestAlgorithm != null) {
            configErrors.add("Can not specify both SIGNATUREALGORITHM and DIGESTALGORITHM at the same time");
        }

        tsaURL = config.getProperty(TSA_URL, DEFAULT_NULL);
        tsaWorker = config.getProperty(TSA_WORKER, DEFAULT_NULL);
        tsaUsername = config.getProperty(TSA_USERNAME, DEFAULT_NULL);
        tsaPassword = config.getPropertyThatCouldBeEmpty(TSA_PASSWORD); // Might be empty string
        final String tsaDigestAlgorithmString =
                config.getProperty(TSA_DIGESTALGORITHM, DigestAlgorithm.SHA256.getName());
        try {
            tsaDigestAlgorithm =
                    DigestAlgorithm.valueOf(tsaDigestAlgorithmString.trim());
        } catch (IllegalArgumentException e) {
            configErrors.add("Unknown TSA digest algorithm: " +
                             tsaDigestAlgorithmString);
        }

        // check that TSA_URL and TSA_WORKER is not set at the same time
        if (tsaURL != null && tsaWorker != null) {
            configErrors.add("Can not specify both " + TSA_URL + " and " + TSA_WORKER + " at the same time.");
        }

        final String addContentTimestampString =
                config.getProperty(ADD_CONTENT_TIMESTAMP,
                                   Boolean.FALSE.toString());
        if (Boolean.FALSE.toString().equalsIgnoreCase(addContentTimestampString)) {
            addContentTimestamp = false;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(addContentTimestampString)) {
            addContentTimestamp = true;
        } else {
            configErrors.add("Incorrect value for property " +
                             ADD_CONTENT_TIMESTAMP +
                             ". Expecting TRUE or FALSE.");
        }

        /* check that when signature level requires timestamping, a TSA has been
         * configured
         */
        if (TIMESTAMPING_REQUIRED.contains(signatureLevel)) {
            if (tsaWorker == null && tsaURL == null) {
                configErrors.add("When using signature level above BASELINE-B, timestamping must be enabled (TSA_WORKER or TSA_URL set)");
            }
        }

        final String trustanchorsString = config.getProperty(TRUSTANCHORS);

        if (StringUtils.isNotBlank(trustanchorsString)) {
            try {
                final byte[] bytes =
                        trustanchorsString.getBytes(StandardCharsets.US_ASCII);
                final InputStream is = new ByteArrayInputStream(bytes);

                final List<Certificate> trustanchors =
                        CertTools.getCertsFromPEM(is, Certificate.class);

                trustedCertificates = new LinkedList<>();
                for (final Certificate cert : trustanchors) {
                    final CertificateToken ct =
                            new CertificateToken((X509Certificate) cert);
                    trustedCertificates.add(ct);
                }
            } catch (CertificateParsingException | IllegalArgumentException ex) {
                configErrors.add("Could not parse " + TRUSTANCHORS);
            }
        }
    }

    @Override
    public List<String> getCertificateIssues(List<Certificate> certificateChain) {
        final List<String> results = super.getCertificateIssues(certificateChain);
        if (!certificateChain.isEmpty()) {
            final Certificate signerCert = certificateChain.get(0);

            results.addAll(checkSignerCertificate(signerCert));
        }
        return results;
    }

    private List<String> checkSignerCertificate(final Certificate signerCert) {
        final List<String> results = new LinkedList<>();

        if (signatureLevel == AdESSignatureLevel.BASELINE_LT) {
            final String authorityInformationAccessOcspUrl =
                CertTools.getAuthorityInformationAccessOcspUrl(signerCert);
            final List<String> cdpUrls = DSSASN1Utils.getCrlUrls(
                    new CertificateToken((X509Certificate) signerCert));

            if (authorityInformationAccessOcspUrl == null && cdpUrls.isEmpty()) {
                results.add("For signature level BASELINE-LT the signer certificate needs to have an authority information access OCSP URL and/or certificate distribution point (CDP) URL extension");
            }
        }

        return results;
    }

    OCSPDataLoader createOcspDataLoader() {
        return new OCSPDataLoader();
    }

    DataLoader createCrlDataLoader() {
        return new CommonsDataLoader();
    }

    // TODO Remove commented lines/blocks
    @Override
    public Response processData(Request signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        try {
            if (!configErrors.isEmpty()) {
                throw new SignServerException("Worker is misconfigured");
            }
            if (!(signRequest instanceof SignatureRequest)) {
                throw new IllegalRequestException("Unexpected request type");
            }
            final SignatureRequest request = (SignatureRequest) signRequest;

            // Get the data from request
            final ReadableData requestData = request.getRequestData();
            final WritableData responseData = request.getResponseData();
            //...
            // Log anything interesting from the request to the worker logger
            final LogMap logMap = LogMap.getInstance(requestContext);
            //...

            // Produce the result, ie doing the work...
            Certificate signerCert = null;
            ICryptoInstance cryptoInstance = null;
            File inFile = requestData.getAsFile();
            //
            try (OutputStream out = responseData.getAsOutputStream()) {
                cryptoInstance = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN,
                        signRequest, requestContext);

                final List<Certificate> signerCertChain =
                        getSigningCertificateChain(cryptoInstance);
                final List<Certificate> includedCerts =
                        includedCertificates(signerCertChain);
                final SignatureTokenConnection signingToken =
                        createSigningToken(cryptoInstance.getPrivateKey(),
                                           includedCerts,
                                           (String) logMap.get(IWorkerLogger.LOG_KEYALIAS),
                                           cryptoInstance.getProvider());
                // Create document
                final DSSDocument toSignDocument = new FileDocument(inFile);
                final Object fileNameOriginal = requestContext.get(RequestContext.FILENAME);
                if (fileNameOriginal instanceof String) {
                    toSignDocument.setName((String) fileNameOriginal);
                }

                // We set the signing certificate
                signerCert = signerCertChain.get(0);
                final CertificateToken signingCertificate = new CertificateToken((X509Certificate) signerCert);
                // We set the certificate chain
                final List<CertificateToken> certificateTokens = createCertificateTokenList(includedCerts);

                // Preparing parameters for the PAdES/XAdES signature
                AdESSignatureParameters parameters = AdESSignatureParameters.builder()
                        .withAdESSignatureLevel(signatureLevel)
                        .withAdESSignatureFormat(signatureFormat)
                        .withSignatureAlgorithm(signatureAlgorithm)
                        .withDigestAlgorithm(digestAlgorithm)
                        .withSigningCertificate(signingCertificate)
                        .withCertificateChain(certificateTokens)
                        .withAddContentTimestamp(addContentTimestamp)
                        .withTSADigestAlgorithm(tsaDigestAlgorithm)
                        .withSignaturePackaging(signaturePackaging)
                        .withExtraSignatureSpace(extraSignatureSpace)
                        .build();

                // Create common certificate verifier
                final CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

                // Create PAdESService for signature
                final AdESService service = new AdESService(signatureFormat, commonCertificateVerifier);

                // set timestamping, when required
                TSPSource tspSource = null;
                if (TIMESTAMPING_REQUIRED.contains(signatureLevel)) {
                    tspSource = createTSPSource(requestContext);
                    service.setTspSource(tspSource);
                }

                final CommonTrustedCertificateSource tslCertificateSource =
                        new CommonTrustedCertificateSource();
                // always add out own issuer as trusted
                final Certificate root =
                        signerCertChain.get(signerCertChain.size() - 1);
                final CertificateToken rootToken =
                        new CertificateToken((X509Certificate) root);

                tslCertificateSource.addCertificate(rootToken);
                // add additional trusted root certs
                if (trustedCertificates != null) {
                    trustedCertificates.forEach(tslCertificateSource::addCertificate);
                }

                commonCertificateVerifier.setTrustedCertSources(tslCertificateSource);

                if (REVOCATION_REQUIRED.contains(signatureLevel)) {
                    final String authorityInformationAccessOcspUrl =
                            CertTools.getAuthorityInformationAccessOcspUrl(signerCert);
                    final List<String> cdpUrls = DSSASN1Utils.getCrlUrls(signingCertificate);

                    if (authorityInformationAccessOcspUrl == null && cdpUrls.isEmpty()) {
                        throw new SignServerException("Missing authority information access OCSP URL or CRL distribution point URL in signer certificate");
                    }

                    final OnlineOCSPSource ocspSource = new OnlineOCSPSource();
                    final OCSPDataLoader ocspDataLoader = createOcspDataLoader();

                    ocspSource.setDataLoader(ocspDataLoader);
                    commonCertificateVerifier.setOcspSource(ocspSource);
                    commonCertificateVerifier.setCrlSource(new OnlineCRLSource(createCrlDataLoader()));
                }

                if (addContentTimestamp) {
                    if (tspSource == null) {
                        tspSource = createTSPSource(requestContext);
                        service.setTspSource(tspSource);
                    }
                    // Allows setting of content-timestamp (part of the signed attributes)
                    TimestampToken contentTimestamp = service.getContentTimestamp(toSignDocument, parameters);
                    parameters.setContentTimestamps(Collections.singletonList(contentTimestamp));
                }

                // Get the SignedInfo segment that need to be signed.
                final ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

                // TODO Here
                // This function obtains the signature value for signed information using the
                // private key and specified algorithm
                final DigestAlgorithm digestAlg = parameters.getDigestAlgorithm();
                final MaskGenerationFunction mgf = parameters.getMaskGenerationFunction();
                final SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlg, mgf, signingToken.getKeys().get(0));

                // Optionally or for debug purpose :
                // Validate the signature value against the original dataToSign
                if (!service.isValidSignatureValue(dataToSign, signatureValue, signingCertificate)) {
                    throw new SignServerException("Assertion failed: verifying our own signature");
                }

                // We invoke the service to sign the document with the signature value obtained in
                // the previous step.
                DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

                signedDocument.writeTo(out);

            } finally {
                releaseCryptoInstance(cryptoInstance, requestContext);
            }

            // Suggest new file name
            suggestNewFileName(requestContext);

            // As everything went well, the client can be charged for the request
            requestContext.setRequestFulfilledByWorker(true);

            // Return the response
            return createBasicSignatureResponse(requestContext, request,
                                              getContentType(signatureFormat),
                                              getContentType(signatureFormat),
                                              signerCert);
        } catch (IOException ex) {
            throw new SignServerException("Encoding error", ex);
        } catch (DSSException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Processing failure: " + ex.getMessage(), ex);
            }
            throw new SignServerException("Processing failure", ex);
        }
    }

    private TSPSource createTSPSource(final RequestContext requestContext)
            throws MalformedURLException {
        if (tsaURL != null) {
            return new ExternalTSPSource(tsaURL, tsaUsername, tsaPassword);
        } else {
            return new InternalTSPSource(tsaWorker, tsaUsername, tsaPassword,
                                         getWorkerSession(requestContext));
        }
    }

    InternalProcessSessionLocal getWorkerSession(final RequestContext requestContext) {
        return requestContext.getServices().get(InternalProcessSessionLocal.class);
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        // Add our errors to the list of errors
        final LinkedList<String> errors = new LinkedList<>(
                super.getFatalErrors(services));
        errors.addAll(configErrors);

        try {
            final Certificate certificate = getSigningCertificate(services);

            errors.addAll(checkSignerCertificate(certificate));
        } catch (CryptoTokenOfflineException e) {
            if (isCryptoTokenActive(services)) {
                errors.add("No signer certificate available");
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Signer " + workerId +
                          ": Could not get signer certificate: " +
                          e.getMessage());
            }
        }
        return errors;
    }

    private static List<CertificateToken> createCertificateTokenList(List<Certificate> certificateChain) {
        return certificateChain.stream().map(x -> new CertificateToken((X509Certificate) x)).collect(Collectors.toList());
    }

    private SignatureTokenConnection createSigningToken(PrivateKey privateKey, List<Certificate> chain, String alias, Provider signatureProvider) {
        return new SinglePrivateKeyEntrySignatureTokenConnection(alias, privateKey, chain, signatureProvider);
    }

    private String getContentType(final AdESSignatureFormat adESSignatureFormat) {
        switch (adESSignatureFormat) {
            case PAdES:
                return MediaType.APPLICATION_PDF;
            case XAdES:
                return MediaType.APPLICATION_XML;
            default:
                throw new IllegalArgumentException("Cannot resolve corresponding ContentType for " + adESSignatureFormat);
        }
    }
}
