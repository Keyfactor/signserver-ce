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
package org.signserver.module.jarchive.signer;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipException;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.log.LogMap;
import org.signserver.server.signers.BaseSigner;
import org.signserver.module.jarchive.impl.signapk.SignApkSigner;
import static org.signserver.server.CredentialUtils.HTTP_AUTH_BASIC_AUTHORIZATION;
import org.signserver.server.IServices;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.server.data.impl.UploadUtil;
import org.signserver.common.data.WritableData;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.Loggable;
import org.signserver.server.tsa.InternalTimeStampTokenFetcher;

/**
 * Signer for JAR files.
 *
 * https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html
 * https://developer.android.com/tools/publishing/app-signing.html
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class JArchiveSigner extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(JArchiveSigner.class);

    // Worker properties
    public static final String PROPERTY_SIGNATUREALGORITHM
            = "SIGNATUREALGORITHM";
    public static final String PROPERTY_DIGESTALGORITHM
            = "DIGESTALGORITHM";
    public static final String PROPERTY_ZIPALIGN
            = "ZIPALIGN";
    public static final String PROPERTY_KEEPSIGNATURES
            = "KEEPSIGNATURES";
    public static final String PROPERTY_REPLACESIGNATURE
            = "REPLACESIGNATURE";
    public static final String PROPERTY_SIGNATURE_NAME_TYPE
            = "SIGNATURE_NAME_TYPE";
    public static final String PROPERTY_SIGNATURE_NAME_VALUE
            = "SIGNATURE_NAME_VALUE";

    public static final String TSA_URL = "TSA_URL";
    public static final String TSA_USERNAME = "TSA_USERNAME";
    public static final String TSA_PASSWORD = "TSA_PASSWORD";
    public static final String TSA_WORKER = "TSA_WORKER";
    public static final String TSA_POLICYOID = "TSA_POLICYOID";

    /** If the request digest should be created and logged. */
    public static final String DO_LOGREQUEST_DIGEST = "DO_LOGREQUEST_DIGEST";

    /** If the response digest should be created and logged. */
    public static final String DO_LOGRESPONSE_DIGEST = "DO_LOGRESPONSE_DIGEST";


    // Log fields

    /** Algorithm for the request digest put in the log. */
    public static final String LOGREQUEST_DIGESTALGORITHM_PROPERTY = "LOGREQUEST_DIGESTALGORITHM";

    /** Algorithm for the request digest put in the log. */
    public static final String LOGRESPONSE_DIGESTALGORITHM_PROPERTY = "LOGRESPONSE_DIGESTALGORITHM";

    // Default values
    private static final String DEFAULT_SIGNATUREALGORITHM = "SHA256withRSA";
    private static final String DEFAULT_DIGESTALGORITHM = "SHA-256";
    private static final boolean DEFAULT_ZIPALIGN = false;
    private static final boolean DEFAULT_KEEPSIGNATURES = true;
    private static final boolean DEFAULT_REPLACESIGNATURE = true;
    private static final SignatureNameType DEFAULT_SIGNATURE_NAME_TYPE = SignatureNameType.KEYALIAS;

    private static final boolean DEFAULT_DO_LOGREQUEST_DIGEST = true;
    private static final String DEFAULT_LOGREQUEST_DIGESTALGORITHM = "SHA256";
    private static final boolean DEFAULT_DO_LOGRESPONSE_DIGEST = true;
    private static final String DEFAULT_LOGRESPONSE_DIGESTALGORITHM = "SHA256";

    // Content types
    private static final String REQUEST_CONTENT_TYPE = "application/zip";
    private static final String RESPONSE_CONTENT_TYPE = "application/java-archive";

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    private String signatureAlgorithm;
    private String digestAlgorithm;
    private boolean zipAlign;
    private boolean keepSignatures;
    private boolean replaceSignature;
    private SignatureNameType signatureNameType;
    private String signatureNameValue;

    private String tsaURL;
    private String tsaWorker;
    private String tsaUsername;
    private String tsaPassword;
    private ASN1ObjectIdentifier tsaPolicyOID;

    private String logRequestDigestAlgorithm;
    private String logResponseDigestAlgorithm;
    private boolean doLogRequestDigest;
    private boolean doLogResponseDigest;

    public enum SignatureNameType {
        /** Fixed value. */
        VALUE,

        /** Fixed value followed/truncated with a numeric value. */
        //PREFIX,

        /** Use the key alias (truncated to 8 characters and with special characters removed). */
        KEYALIAS,

        /** Use the key alias followed/truncated with a numeric value. */
        //KEYALIAS_PREFIX
    }

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Optional property SIGNATUREALGORITHM
        signatureAlgorithm = config.getProperty(PROPERTY_SIGNATUREALGORITHM);
        if (signatureAlgorithm == null || signatureAlgorithm.trim().isEmpty()) {
            signatureAlgorithm = DEFAULT_SIGNATUREALGORITHM;
        }

        // Optional property DIGESTALGORITHM
        digestAlgorithm = config.getProperty(PROPERTY_DIGESTALGORITHM); // TODO: This should be of form: "SHA1, SHA-256, SHA-512" etc? Maybe need change from "SHA256"->"SHA-256" and from OID
        if (digestAlgorithm == null || digestAlgorithm.trim().isEmpty()) {
            digestAlgorithm = DEFAULT_DIGESTALGORITHM;
        }

        // Optional property ZIPALIGN
        String value = config.getProperty(PROPERTY_ZIPALIGN);
        if (value == null || value.trim().isEmpty()) {
            zipAlign = DEFAULT_ZIPALIGN;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(value.trim())) {
            zipAlign = true;
        } else if (Boolean.FALSE.toString().equalsIgnoreCase(value.trim())) {
            zipAlign = false;
        } else {
            configErrors.add("Incorrect value for property " + PROPERTY_ZIPALIGN);
        }

        // Optional property KEEPSIGNATURES
        value = config.getProperty(PROPERTY_KEEPSIGNATURES);
        if (value == null || value.trim().isEmpty()) {
            keepSignatures = DEFAULT_KEEPSIGNATURES;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(value.trim())) {
            keepSignatures = true;
        } else if (Boolean.FALSE.toString().equalsIgnoreCase(value.trim())) {
            keepSignatures = false;
        } else {
            configErrors.add("Incorrect value for property " + PROPERTY_KEEPSIGNATURES);
        }

        // Optional property REPLACESIGNATURE
        value = config.getProperty(PROPERTY_REPLACESIGNATURE);
        if (value == null || value.trim().isEmpty()) {
            replaceSignature = DEFAULT_REPLACESIGNATURE;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(value.trim())) {
            replaceSignature = true;
        } else if (Boolean.FALSE.toString().equalsIgnoreCase(value.trim())) {
            replaceSignature = false;
        } else {
            configErrors.add("Incorrect value for property " + PROPERTY_REPLACESIGNATURE);
        }

        // Optional property SIGNATURE_NAME_TYPE
        try {
            value = config.getProperty(PROPERTY_SIGNATURE_NAME_TYPE);
            if (value == null || value.trim().isEmpty()) {
                signatureNameType = DEFAULT_SIGNATURE_NAME_TYPE;
            } else {
                signatureNameType = SignatureNameType.valueOf(value.trim());
            }

            // Conditionally optional property SIGNATURE_NAME_VALUE
            signatureNameValue = config.getProperty(PROPERTY_SIGNATURE_NAME_VALUE);
            if (signatureNameValue == null || signatureNameValue.trim().isEmpty()) {
                signatureNameValue = null;
            }
            switch (signatureNameType) {
                // Expect no value for KEYALIAS
                case KEYALIAS: {
                    if (signatureNameValue != null) {
                        configErrors.add("No value for " + PROPERTY_SIGNATURE_NAME_VALUE + " expected when " + PROPERTY_SIGNATURE_NAME_TYPE + " is " + SignatureNameType.KEYALIAS);
                    }
                    break;
                }

                // Require value for VALUE
                case VALUE: {
                    if (signatureNameValue == null) {
                        configErrors.add("Missing value for " + PROPERTY_SIGNATURE_NAME_VALUE + " when " + PROPERTY_SIGNATURE_NAME_TYPE + " is " + SignatureNameType.VALUE);
                    } else {
                        String cleanedValue = convertToValidSignatureName(signatureNameValue);
                        if (!cleanedValue.equals(signatureNameValue)) {
                            configErrors.add("Incorrect value for property " + PROPERTY_SIGNATURE_NAME_VALUE + ". Valid values are maximum 8 characters from 'A-Z0-9_-.'. Use the following value: " + cleanedValue);
                        }
                    }
                }
            }
        } catch (IllegalArgumentException ex) {
            configErrors.add("Incorrect value for property " + PROPERTY_SIGNATURE_NAME_TYPE + ". Possible values are: " + Arrays.asList(SignatureNameType.values()));
        }

        // Get the log digest algorithms
        logRequestDigestAlgorithm = config.getProperty(LOGREQUEST_DIGESTALGORITHM_PROPERTY);
        if (logRequestDigestAlgorithm == null || logRequestDigestAlgorithm.trim().isEmpty()) {
            logRequestDigestAlgorithm = DEFAULT_LOGREQUEST_DIGESTALGORITHM;
        }
        logResponseDigestAlgorithm = config.getProperty(LOGRESPONSE_DIGESTALGORITHM_PROPERTY);
        if (logResponseDigestAlgorithm == null || logResponseDigestAlgorithm.trim().isEmpty()) {
            logResponseDigestAlgorithm = DEFAULT_LOGRESPONSE_DIGESTALGORITHM;
        }

        tsaURL = config.getProperty(TSA_URL);
        if (tsaURL != null && tsaURL.trim().isEmpty()) {
            tsaURL = null;
        }
        tsaWorker = config.getProperty(TSA_WORKER);
        if (tsaWorker != null && tsaWorker.trim().isEmpty()) {
            tsaWorker = null;
        }
        tsaUsername = config.getProperty(TSA_USERNAME);
        if (tsaUsername != null && tsaUsername.trim().isEmpty()) {
            tsaUsername = null;
        }
        tsaPassword = config.getProperty(TSA_PASSWORD); // Might be empty string
        value = config.getProperty(TSA_POLICYOID);
        if (value == null || value.trim().isEmpty()) {
            tsaPolicyOID = null;
        } else {
            try {
                tsaPolicyOID = new ASN1ObjectIdentifier(value);
            } catch (IllegalArgumentException ex) {
                configErrors.add("Incorrect value for " + TSA_POLICYOID + ": " + ex.getLocalizedMessage());
            }
        }

        // check that TSA_URL and TSA_WORKER is not set at the same time
        if (tsaURL != null && tsaWorker != null) {
            configErrors.add("Can not specify both " + TSA_URL + " and " + TSA_WORKER + " at the same time.");
        }

        // Check that password is specified if username is
        if (tsaUsername != null && tsaPassword == null) {
            configErrors.add("Need to specify " + TSA_PASSWORD + " if " + TSA_USERNAME + " is specified.");
        }

        // If the request digest should computed and be logged
        String s = config.getProperty(DO_LOGREQUEST_DIGEST);
        if (s == null || s.trim().isEmpty()) {
            doLogRequestDigest = DEFAULT_DO_LOGREQUEST_DIGEST;
        } else if ("true".equalsIgnoreCase(s)) {
            doLogRequestDigest = true;
        } else if ("false".equalsIgnoreCase(s)) {
            doLogRequestDigest = false;
        } else {
            configErrors.add("Incorrect value for " + DO_LOGREQUEST_DIGEST);
        }

        // If the response digest should computed and be logged
        s = config.getProperty(DO_LOGRESPONSE_DIGEST);
        if (s == null || s.trim().isEmpty()) {
            doLogResponseDigest = DEFAULT_DO_LOGRESPONSE_DIGEST;
        } else if ("true".equalsIgnoreCase(s)) {
            doLogResponseDigest = true;
        } else if ("false".equalsIgnoreCase(s)) {
            doLogResponseDigest = false;
        } else {
            configErrors.add("Incorrect value for " + DO_LOGRESPONSE_DIGEST);
        }

        // additionally check that at least one certificate is included.
        // (initIncludeCertificateLevels already checks non-negative values)
        if (hasSetIncludeCertificateLevels && includeCertificateLevels == 0) {
            configErrors.add("Illegal value for property " + WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS + ". Only numbers >= 1 supported.");
        }
    }

    @Override
    public Response processData(Request signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {

        if (!(signRequest instanceof SignatureRequest)) {
            throw new IllegalRequestException("Unexpected request type");
        }
        final SignatureRequest sReq = (SignatureRequest) signRequest;
        
        if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }

        // Get the data from request
        final ReadableData data = sReq.getRequestData();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Request size: " + data.getLength());
        }
        final WritableData responseData = sReq.getResponseData();

        // Log anything interesting from the request to the worker logger
        final LogMap logMap = LogMap.getInstance(requestContext);

        final byte[] requestDigest;
        if (doLogRequestDigest) {
            logMap.put(IWorkerLogger.LOG_REQUEST_DIGEST_ALGORITHM, logRequestDigestAlgorithm);
            
            try (InputStream input = data.getAsInputStream()) {
                final MessageDigest md = MessageDigest.getInstance(logRequestDigestAlgorithm);
                
                // Digest all data
                // TODO: Future optimization: could be done while the file is read instead
                requestDigest = UploadUtil.digest(input, md);

                logMap.put(IWorkerLogger.LOG_REQUEST_DIGEST, new Loggable() {
                    @Override
                    public String toString() {
                        return Hex.toHexString(requestDigest);
                    }
                });
            } catch (NoSuchAlgorithmException ex) {
                LOG.error("Log digest algorithm not supported", ex);
                throw new SignServerException("Log digest algorithm not supported", ex);
            } catch (IOException ex) {
                LOG.error("Log request digest failed", ex);
                throw new SignServerException("Log request digest failed", ex);
            }
        }

        // Produce the result, ie doing the work...
        Certificate signerCert = null;
        ICryptoInstance cryptoInstance = null;
        File inFile = null;
        File outFile = null;
        SignApkSigner signer;
        final String archiveId;

        try {
            cryptoInstance = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, signRequest, requestContext);

            // Get certificate chain and signer certificate
            List<Certificate> certs = getSigningCertificateChain(cryptoInstance);
            if (certs == null || certs.isEmpty()) {
                throw new IllegalArgumentException("No certificate chain. This signer needs a certificate.");
            }
            signerCert = certs.get(0);
            if (LOG.isDebugEnabled()) {
                LOG.debug("SigningCert: " + ((X509Certificate) signerCert).getSubjectDN());
            }

            certs = includedCertificates(certs);

            // XXX: Better idea?
            X509Certificate[] xcerts = new X509Certificate[certs.size()];
            for (int i = 0; i < certs.size(); i++) {
                xcerts[i] = (X509Certificate) certs.get(i);
            }

            // Private key
            PrivateKey privKey = cryptoInstance.getPrivateKey();

            inFile = data.getAsFile();
            outFile = responseData.getAsFile();

            // Get name to use for the signature
            String signatureName;
            if (signatureNameType == SignatureNameType.VALUE) {
                signatureName = signatureNameValue;
            } else {
                final Object loggable = logMap.get(IWorkerLogger.LOG_KEYALIAS);

                if (loggable == null) {
                    throw new SignServerException(PROPERTY_SIGNATURE_NAME_TYPE + " is " + signatureNameType.name() + " but no key alias is availble to use as the name");
                }

                signatureName = convertToValidSignatureName(loggable.toString());
            }

            // Implementation with or without time-stamp
            if (tsaURL != null) {
                signer = new ExternalTimeStampingSigner(privKey, xcerts, cryptoInstance.getProvider(), signatureAlgorithm, digestAlgorithm, zipAlign, keepSignatures, replaceSignature, signatureName, tsaPolicyOID, tsaUsername, tsaPassword, new URL(tsaURL));
            } else if (tsaWorker != null) {
                signer = new InternalTimeStampingSigner(privKey, xcerts, cryptoInstance.getProvider(), signatureAlgorithm, digestAlgorithm, zipAlign, keepSignatures, replaceSignature, signatureName, tsaPolicyOID, tsaUsername, tsaPassword, new WorkerIdentifier(tsaWorker), requestContext.getServices().get(InternalProcessSessionLocal.class));
            } else {
                signer = new SignApkSigner(privKey, xcerts, cryptoInstance.getProvider(), signatureAlgorithm, digestAlgorithm, false, zipAlign, keepSignatures, replaceSignature, signatureName, tsaPolicyOID) {
                    @Override
                    protected byte[] timestamp(byte[] imprint, ASN1ObjectIdentifier digestAlgorithm, ASN1ObjectIdentifier reqPolicy) throws IOException, SignServerException {
                        throw new UnsupportedOperationException("Time-stamping not supported");
                    }
                };
            }

            signer.sign(inFile, outFile);

            // TODO: Future optimization: For performance reasons, instead of
            // hashing the document again and use that in the archive id, we
            // should be able to somehow get the already hashed value from the
            // signing implementation or to extract the digest from the
            // SignedData structure
            archiveId = createArchiveId(/*signer.getCachedDigest()*/ /*data*/ new byte[0], (String) requestContext.get(RequestContext.TRANSACTION_ID));

            final byte[] responseDigest;
            if (doLogResponseDigest) {
                logMap.put(IWorkerLogger.LOG_RESPONSE_DIGEST_ALGORITHM, logResponseDigestAlgorithm);

                try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(outFile))) {
                    final MessageDigest md = MessageDigest.getInstance(logResponseDigestAlgorithm);
                    responseDigest = UploadUtil.digest(in, md);

                    logMap.put(IWorkerLogger.LOG_RESPONSE_DIGEST,
                               new Loggable() {
                                   @Override
                                   public String toString() {
                                        return Hex.toHexString(responseDigest);
                                   }
                               });
                } catch (NoSuchAlgorithmException ex) {
                    LOG.error("Log digest algorithm not supported", ex);
                    throw new SignServerException("Log digest algorithm not supported", ex);
                }
            }

        } catch (ZipException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Parse error", ex);
            }
            throw new IllegalRequestException("Unable to parse ZIP file", ex);
        } catch (IOException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("IO error", ex);
            }
            throw new SignServerException(ex.getMessage());
        } catch (CMSException | OperatorCreationException | GeneralSecurityException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unexpected error", ex);
            }
            throw new SignServerException(ex.getMessage(), ex);
        } finally {
            if (cryptoInstance != null) {
                releaseCryptoInstance(cryptoInstance, requestContext);
            }
        }

        final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST, REQUEST_CONTENT_TYPE, data, archiveId),
                    new DefaultArchivable(Archivable.TYPE_RESPONSE, RESPONSE_CONTENT_TYPE, responseData.toReadableData(), archiveId));

        // The client can be charged for the request
        requestContext.setRequestFulfilledByWorker(true);

        // Return the response
        return new SignatureResponse(sReq.getRequestID(), responseData, signerCert, archiveId, archivables, RESPONSE_CONTENT_TYPE);
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        // Add our errors to the list of errors
        final LinkedList<String> errors = new LinkedList<>(
                super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }

    /**
     * Signer that fetches timestamps from a TimeStampSigner in SignServer.
     */
    public static class InternalTimeStampingSigner extends SignApkSigner {

        private final InternalTimeStampTokenFetcher fetcher;

        public InternalTimeStampingSigner(PrivateKey privateKey, X509Certificate[] certificates, Provider provider, String signatureAlgorithm, String digestAlgorithm, boolean zipAlign, boolean keepSignatures, boolean replaceSignature, String signatureName, ASN1ObjectIdentifier reqPolicy, String username, String password, WorkerIdentifier wi, InternalProcessSessionLocal processSession) {
            super(privateKey, certificates, provider, signatureAlgorithm, digestAlgorithm, true, zipAlign, keepSignatures, replaceSignature, signatureName, reqPolicy);
            this.fetcher = new InternalTimeStampTokenFetcher(processSession, wi, username, password);
        }

        @Override
        protected byte[] timestamp(byte[] imprint, ASN1ObjectIdentifier digestAlgorithm, ASN1ObjectIdentifier reqPolicy) throws IOException, SignServerException {
            try {
                return fetcher.fetchToken(imprint, digestAlgorithm, reqPolicy).getEncoded();
            } catch (IllegalRequestException ex) {
                throw new SignServerException("The time-stamp request failed", ex);
            } catch (CryptoTokenOfflineException ex) {
                throw new SignServerException("The time-stamp request could not be processed because of offline TSA", ex);
            } catch (TSPException ex) {
                throw new SignServerException("Invalid time stamp response", ex);
            }
        }
    }

    /**
      * Signer that fetches timestamps from an URL.
     */
    public static class ExternalTimeStampingSigner extends SignApkSigner {

        private final String basicAuthorization;
        private final URL url;

        public ExternalTimeStampingSigner(PrivateKey privateKey, X509Certificate[] certificates, Provider provider, String signatureAlgorithm, String digestAlgorithm, boolean zipAlign, boolean keepSignatures, boolean replaceSignature, String signatureName, ASN1ObjectIdentifier reqPolicy, String username, String password, URL url) {
            super(privateKey, certificates, provider, signatureAlgorithm, digestAlgorithm, true, zipAlign, keepSignatures, replaceSignature, signatureName, reqPolicy);
            this.url = url;
            if (username == null) {
                basicAuthorization = null;
            } else {
                final String usrAndPwd = username + ":" + password;
                this.basicAuthorization = Base64.toBase64String(usrAndPwd.getBytes());
            }
        }

        @Override
        protected byte[] timestamp(byte[] imprint, ASN1ObjectIdentifier digestAlgorithm, ASN1ObjectIdentifier reqPolicy) throws IOException, SignServerException  {
            try {
                final TimeStampRequestGenerator timeStampRequestGenerator =
                        new TimeStampRequestGenerator();
                final TimeStampRequest timeStampRequest;

                BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());

                timeStampRequestGenerator.setCertReq(true);

                if (reqPolicy != null) {
                    timeStampRequestGenerator.setReqPolicy(reqPolicy);
                }

                timeStampRequest = timeStampRequestGenerator.generate(
                        TSPAlgorithms.SHA1, imprint, nonce);

                final byte[] requestBytes = timeStampRequest.getEncoded();

                HttpURLConnection urlConn;
                DataOutputStream printout;
                DataInputStream input;

                // Take start time
                final long startMillis = System.currentTimeMillis();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Sending request at: " + startMillis);
                }

                urlConn = (HttpURLConnection) url.openConnection();

                urlConn.setDoInput(true);
                urlConn.setDoOutput(true);
                urlConn.setUseCaches(false);
                urlConn.setRequestProperty("Content-Type",
                        "application/timestamp-query");

                if (this.basicAuthorization != null) {
                    urlConn.setRequestProperty(HTTP_AUTH_BASIC_AUTHORIZATION, "Basic " + this.basicAuthorization);
                }

                // Send POST output.
                printout = new DataOutputStream(urlConn.getOutputStream());
                printout.write(requestBytes);
                printout.flush();
                printout.close();

                // Get response data.
                final int responseCode = urlConn.getResponseCode();

                if (responseCode >= 400) {
                    input = new DataInputStream(urlConn.getErrorStream());
                } else {
                    input = new DataInputStream(urlConn.getInputStream());
                }

                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                int b;
                while ((b = input.read()) != -1) {
                    baos.write(b);
                }

                if (responseCode >= 400) {
                    throw new IOException("HTTP Error " + responseCode + " for URL " + url + ": " +  urlConn.getResponseMessage());
                }

                // Take stop time
                final long estimatedTime = System.nanoTime() - startMillis;

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Got reply after "
                        + TimeUnit.NANOSECONDS.toMillis(estimatedTime) + " ms");
                }

                final byte[] replyBytes = baos.toByteArray();

                final TimeStampResponse timeStampResponse = new TimeStampResponse(
                        replyBytes);
                timeStampResponse.validate(timeStampRequest);

                final int status = timeStampResponse.getStatus();
                final PKIFailureInfo failInfo = timeStampResponse.getFailInfo();

                if (LOG.isDebugEnabled()) {
                    final String statusString = timeStampResponse.getStatusString();
                    final Date genTime;
                    if (timeStampResponse.getTimeStampToken() != null && timeStampResponse.getTimeStampToken().getTimeStampInfo() != null) {
                        genTime = timeStampResponse.getTimeStampToken().getTimeStampInfo().getGenTime();
                    } else {
                        genTime = null;
                    }
                    LOG.debug("(Status: " + status
                            + ", " + failInfo + "): "
                            + statusString + (genTime != null ? (", genTime: " + genTime.getTime()) : "") + "\n");
                }

                return timeStampResponse.getTimeStampToken().getEncoded();
            } catch (TSPException ex) {
                throw new SignServerException("Incorrect time-stamp response", ex);
            }
        }
    }

    /**
     * Convert the input string so that it is maximum 8 characters from 
     * 'A-Z0-9_- and minimum one character. Other characters are converted to
     * underscore and empty String converted to one underscore.
     * @param signatureNameValue to convert
     * @return the converted String
     */
    protected static String convertToValidSignatureName(String signatureNameValue) {
        String result;
        if (signatureNameValue.isEmpty()) {
            // Special case for empty
            result = "_";
        } else {
            // Convert to upper case, note we only allow A-Z so English locale should be fine
            signatureNameValue = signatureNameValue.toUpperCase(Locale.ENGLISH);

            // Truncate if needed
            if (signatureNameValue.length() > 8) {
                result = signatureNameValue.substring(0, 8);
            } else {
                result = signatureNameValue;
            }

            // Replace other characters
            result = result.replaceAll("[^a-zA-Z0-9_.-]", "_"); // TODO: Performance replace with static pattern matcher
        }

        return result;
    }
}
