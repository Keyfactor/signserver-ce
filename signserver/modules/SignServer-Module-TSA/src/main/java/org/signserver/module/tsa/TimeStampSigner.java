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
package org.signserver.module.tsa;

import org.apache.commons.lang.ArrayUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.signserver.module.cmssigner.FilteredSignedAttributeTableGenerator;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.cesecore.util.Base64;
import org.signserver.common.*;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.signserver.server.IServices;
import org.signserver.server.ITimeSource;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.server.log.ExceptionLoggable;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;
import org.signserver.server.signers.BaseSigner;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;

/**
 * A Signer signing Time-stamp request according to RFC 3161 using the
 * BouncyCastle TimeStamp API.
 *
 * Implements a ISigner and have the following properties:
 *
 * <table border="1">
 *  <tr>
 *      <td>TIMESOURCE</td>
 *      <td>
 *          property containing the classpath to the ITimeSource implementation
 *          that should be used. (default LocalComputerTimeSource)
 *      </td>
 *  </tr>
 *  <tr>
 *      <td>ACCEPTEDALGORITHMS</td>
 *      <td>
 *          A ';' separated string containing accepted algorithms, can be null
 *          if it shouldn't be used. (OPTIONAL)
 *      </td>
 *  </tr>
 *  <tr>
 *      <td>ACCEPTEDPOLICIES</td>
 *      <td>
 *          A ';' separated string containing accepted policies, can be null if
 *          it shouldn't be used. (OPTIONAL)
 *      </td>
 * </tr>
 *  <tr>
 *      <td>ACCEPTEDEXTENSIONS</td>
 *      <td>
 *          A ';' separated string containing accepted extensions, can be null
 *          if it shouldn't be used. (OPTIONAL)
 *      </td>
 * </tr>
 *  <tr>
 *      <td>DIGESTOID</td>
 *      <td>
 *          The Digest OID to be used in the timestamp
 *      </td>
 * </tr>
 *  <tr>
 *      <td>DEFAULTTSAPOLICYOID</td>
 *      <td>
 *          The default policy ID of the time stamp authority
 *      </td>
 * </tr>
 *  <tr>
 *      <td>ACCURACYMICROS</td>
 *      <td>
 *          Accuracy in micro seconds, Only decimal number format, only one of
 *          the accuracy properties should be set (OPTIONAL)
 *      </td>
 * </tr>
 *  <tr>
 *      <td>ACCURACYMILLIS</td>
 *      <td>
 *          Accuracy in milli seconds, Only decimal number format, only one of
 *          the accuracy properties should be set (OPTIONAL)
 *      </td>
 * </tr>
 *  <tr>
 *      <td>ACCURACYSECONDS</td>
 *      <td>
 *          Accuracy in seconds. Only decimal number format, only one of the
 *          accuracy properties should be set (OPTIONAL)
 *      </td>
 * </tr>
 *  <tr>
 *      <td>ORDERING</td>
 *      <td>
 *          The ordering (OPTIONAL), default false.
 *      </td>
 * </tr>
 *  <tr>
 *      <td>TSA</td>
 *      <td>
 *          General name of the Time Stamp Authority.
 *      </td>
 *  </tr>
 * <tr>
 *      <td>REQUIREVALIDCHAIN</td>
 *      <td>
 *          Set to true to perform an extra check that the SIGNERCERTCHAIN only
 *          contains certificates in the chain of the signer certificate.
 *          (OPTIONAL), default false.
 *      </td>
 * </tr>
 *
 * </table>
 *
 * Specifying a signer certificate (normally the SIGNERCERT property) is required
 * as information from that certificate will be used to indicate which signer
 * signed the time-stamp token.
 *
 * The SIGNERCERTCHAIN property contains all certificates included in the token
 * if the client requests the certificates. The RFC specified that the signer
 * certificate MUST be included in the list returned.
 *
 *
 * @author philip
 * @version $Id$
 */
public class TimeStampSigner extends BaseSigner {

    private static final Logger LOG = Logger.getLogger(TimeStampSigner.class);

    /** Random generator algorithm. */
    private static final String ALGORITHM = "SHA1PRNG";

    /** Random generator. */
    private transient SecureRandom random;

    /** MIME type for the request data. **/
    private static final String REQUEST_CONTENT_TYPE = "application/timestamp-query";

    /** MIME type for the response data. **/
    private static final String RESPONSE_CONTENT_TYPE = "application/timestamp-reply";

    // Property constants
    public static final String TIMESOURCE = "TIMESOURCE";
    public static final String SIGNATUREALGORITHM = "SIGNATUREALGORITHM";
    public static final String ACCEPTEDALGORITHMS = "ACCEPTEDALGORITHMS";
    public static final String ACCEPTEDPOLICIES = "ACCEPTEDPOLICIES";
    public static final String ACCEPTANYPOLICY = "ACCEPTANYPOLICY";
    public static final String ACCEPTEDEXTENSIONS = "ACCEPTEDEXTENSIONS";
    //public static final String DEFAULTDIGESTOID    = "DEFAULTDIGESTOID";
    public static final String DEFAULTTSAPOLICYOID = "DEFAULTTSAPOLICYOID";
    public static final String ACCURACYMICROS = "ACCURACYMICROS";
    public static final String ACCURACYMILLIS = "ACCURACYMILLIS";
    public static final String ACCURACYSECONDS = "ACCURACYSECONDS";
    public static final String ORDERING = "ORDERING";
    public static final String TSA = "TSA";
    public static final String TSA_FROM_CERT = "TSA_FROM_CERT";
    public static final String REQUIREVALIDCHAIN = "REQUIREVALIDCHAIN";
    public static final String VERIFY_TOKEN_SIGNATURE = "VERIFY_TOKEN_SIGNATURE";
    public static final String MAXSERIALNUMBERLENGTH = "MAXSERIALNUMBERLENGTH";
    public static final String INCLUDESTATUSSTRING = "INCLUDESTATUSSTRING";
    public static final String INCLUDESIGNINGTIMEATTRIBUTE = "INCLUDESIGNINGTIMEATTRIBUTE";
    public static final String INCLUDECMSALGORITHMPROTECTATTRIBUTE = "INCLUDECMSALGORITHMPROTECTATTRIBUTE";
    public static final String INCLUDE_CERTID_ISSUERSERIAL = "INCLUDE_CERTID_ISSUERSERIAL";
    public static final String CERTIFICATE_DIGEST_ALGORITHM = "CERTIFICATE_DIGEST_ALGORITHM";

    private static final String DEFAULT_WORKERLOGGER =
            DefaultTimeStampLogger.class.getName();

    private static final String DEFAULT_TIMESOURCE =
            "org.signserver.server.LocalComputerTimeSource";
    private static final int DEFAULT_MAXSERIALNUMBERLENGTH = 8;

    private static final String[] ACCEPTED_ALGORITHMS_NAMES = {
        "GOST3411",
        "MD5",
        "SHA1",
        "SHA224",
        "SHA256",
        "SHA384",
        "SHA512",
        "RIPEMD128",
        "RIPEMD160",
        "RIPEMD256"
    };

    private static final ASN1ObjectIdentifier[] ACCEPTED_ALGORITHMS_OIDS = {
        TSPAlgorithms.GOST3411,
        TSPAlgorithms.MD5,
        TSPAlgorithms.SHA1,
        TSPAlgorithms.SHA224,
        TSPAlgorithms.SHA256,
        TSPAlgorithms.SHA384,
        TSPAlgorithms.SHA512,
        TSPAlgorithms.RIPEMD128,
        TSPAlgorithms.RIPEMD160,
        TSPAlgorithms.RIPEMD256
    };

    private static final HashMap<String, ASN1ObjectIdentifier> ACCEPTED_ALGORITHMS_MAP =
            new HashMap<>();

    static {
        for (int i = 0; i < ACCEPTED_ALGORITHMS_NAMES.length; i++) {
            ACCEPTED_ALGORITHMS_MAP.put(ACCEPTED_ALGORITHMS_NAMES[i],
                    ACCEPTED_ALGORITHMS_OIDS[i]);
        }
    }

    private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String DEFAULT_CERTIFICATE_DIGEST_ALGORITHM = "SHA256";

    private ITimeSource timeSource = null;
    private String signatureAlgorithm;
    private Set<ASN1ObjectIdentifier> acceptedAlgorithms = null;
    private Set<String> acceptedPolicies = null;
    private boolean acceptAnyPolicy = false;
    private Set<String> acceptedExtensions = null;

    //private String defaultDigestOID = null;
    private ASN1ObjectIdentifier defaultTSAPolicyOID = null;

    private boolean validChain = true;

    private int maxSerialNumberLength;

    // we restrict the allowed serial number size limit to between 64 and 160 bits
    // note: the generated serial number will always be positive
    private static final int MAX_ALLOWED_MAXSERIALNUMBERLENGTH = 20;
    private static final int MIN_ALLOWED_MAXSERIALNUMBERLENGTH = 8;

    private boolean includeStatusString;

    private String tsaName;
    private boolean tsaNameFromCert;
    private boolean includeSigningTimeAttribute;
    private boolean includeCmsProtectAlgorithmAttribute;
    private boolean includeCertIDIssuerSerial = true;
    private boolean legacyEncoding;
    private boolean verifyTokenSignature = true;

    private boolean ordering;

    private ASN1ObjectIdentifier certificateDigestAlgorithm;

    List<String> configErrors;

    @Override
    public void init(final int signerId, final WorkerConfig config,
            final WorkerContext workerContext,
            final EntityManager workerEntityManager) {
        super.init(signerId, config, workerContext, workerEntityManager);

        configErrors = new LinkedList<>();

        // Overrides the default worker logger to be this worker
        //  implementation's default instead of the WorkerSessionBean's
        config.setProperty("WORKERLOGGER", config.getProperty("WORKERLOGGER", DEFAULT_WORKERLOGGER));

        // Check that the timestamp server is properly configured
        try {
            timeSource = getTimeSource();
            if (LOG.isDebugEnabled()) {
                LOG.debug("TimeStampSigner[" + signerId + "]: "
                        + "Using TimeSource: "
                        + timeSource.getClass().getName());
            }
        } catch (SignServerException e) {
            configErrors.add("Could not create time source: " + e.getMessage());
        }

        // Get the signature algorithm
        signatureAlgorithm = config.getProperty(SIGNATUREALGORITHM, DEFAULT_SIGNATURE_ALGORITHM);

        /* defaultDigestOID =
            config.getProperties().getProperty(DEFAULTDIGESTOID);
        if (defaultDigestOID == null) {
            defaultDigestOID = DEFAULT_DIGESTOID;
        }*/

        final String policyId = config.getProperty(DEFAULTTSAPOLICYOID, DEFAULT_NULL);

        try {
            if (policyId != null) {
                defaultTSAPolicyOID = new ASN1ObjectIdentifier(policyId);
            } else {
                configErrors.add("No default TSA policy OID has been configured");
            }
        } catch (IllegalArgumentException iae) {
            configErrors.add("TSA policy OID " + policyId + " is invalid: " + iae.getLocalizedMessage());
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("bctsp version: " + TimeStampResponseGenerator.class
                    .getPackage().getImplementationVersion() + ", "
                    + TimeStampRequest.class.getPackage()
                            .getImplementationVersion());
        }

        // Validate certificates in signer certificate chain
        final String requireValidChain = config.getProperty(REQUIREVALIDCHAIN, Boolean.FALSE.toString());
        if (Boolean.parseBoolean(requireValidChain)) {
            validChain = validateChain(null);
        }

        // Whether token signature is to be validated before sending response
        final String verifyTokenSignatureString = config.getProperty(VERIFY_TOKEN_SIGNATURE, Boolean.TRUE.toString()).trim();
        if (Boolean.TRUE.toString().equalsIgnoreCase(verifyTokenSignatureString)) {
            verifyTokenSignature = true;
        } else if (Boolean.FALSE.toString().equalsIgnoreCase(verifyTokenSignatureString)) {
            verifyTokenSignature = false;
        } else {
            configErrors.add("Incorrect value for " + VERIFY_TOKEN_SIGNATURE);
        }

        final String maxSerialNumberLengthProp = config.getProperty(MAXSERIALNUMBERLENGTH, Integer.toString(DEFAULT_MAXSERIALNUMBERLENGTH));

        String serialNumberError = null;
        try {
            maxSerialNumberLength = Integer.parseInt(maxSerialNumberLengthProp);
        } catch (NumberFormatException e) {
            maxSerialNumberLength = -1;
            serialNumberError = "Maximum serial number length specified is invalid: \"" + maxSerialNumberLengthProp + "\"";
        }

        if (serialNumberError == null) {
            if (maxSerialNumberLength > MAX_ALLOWED_MAXSERIALNUMBERLENGTH) {
                serialNumberError = "Maximum serial number length specified is too large: " + maxSerialNumberLength;
            } else if (maxSerialNumberLength < MIN_ALLOWED_MAXSERIALNUMBERLENGTH) {
                serialNumberError = "Maximum serial number length specified is too small: " + maxSerialNumberLength;
            }
        }

        if (serialNumberError != null) {
            configErrors.add(serialNumberError);
        }

        includeStatusString = Boolean.parseBoolean(config.getProperty(INCLUDESTATUSSTRING, "true"));

        tsaName = config.getProperty(TSA, DEFAULT_NULL);
        tsaNameFromCert = Boolean.parseBoolean(config.getProperty(TSA_FROM_CERT, "false"));

        if (tsaName != null && tsaNameFromCert) {
            configErrors.add("Can not set " + TSA_FROM_CERT + " to true and set " + TSA + " worker property at the same time");
        }

        includeSigningTimeAttribute = Boolean.parseBoolean(config.getProperty(INCLUDESIGNINGTIMEATTRIBUTE, "true"));

        includeCmsProtectAlgorithmAttribute = Boolean.parseBoolean(config.getProperty(INCLUDECMSALGORITHMPROTECTATTRIBUTE, "true"));

        ordering = Boolean.parseBoolean(config.getProperty(ORDERING, "false"));

        if (hasSetIncludeCertificateLevels && includeCertificateLevels == 0) {
            configErrors.add("Illegal value for property " + WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS + ". Only numbers >= 1 supported.");
        }

        // Optional property INCLUDE_CERTID_ISSUERSERIAL, default: true
        String value = config.getProperty(INCLUDE_CERTID_ISSUERSERIAL, Boolean.TRUE.toString());
        if (Boolean.TRUE.toString().equalsIgnoreCase(value)) {
            includeCertIDIssuerSerial = true;
        } else if (Boolean.FALSE.toString().equalsIgnoreCase(value)) {
            includeCertIDIssuerSerial = false;
        } else {
            configErrors.add("Illegal value for property " + INCLUDE_CERTID_ISSUERSERIAL);
        }

        final String certificateDigestAlgorithmString =
                config.getProperty(CERTIFICATE_DIGEST_ALGORITHM,
                        DEFAULT_CERTIFICATE_DIGEST_ALGORITHM);
        certificateDigestAlgorithm =
                getCertificateDigestAlgorithmFromString(certificateDigestAlgorithmString);

        final String acceptAnyPolicyValue = config.getProperty(ACCEPTANYPOLICY, Boolean.FALSE.toString());
        final String acceptedPoliciesValue = config.getPropertyThatCouldBeEmpty(ACCEPTEDPOLICIES); // Empty value has a special meaning here so no default

        if (acceptAnyPolicyValue != null) {
            if (Boolean.TRUE.toString().equalsIgnoreCase(acceptAnyPolicyValue)) {
                acceptAnyPolicy = true;
            } else if (Boolean.FALSE.toString().equalsIgnoreCase(acceptAnyPolicyValue)) {
                acceptAnyPolicy = false;
            } else {
                configErrors.add("Illegal value for ACCEPTANYPOLICY: "
                        + acceptAnyPolicyValue);
            }
        }

        if (acceptAnyPolicy && acceptedPoliciesValue != null) {
            configErrors.add("Can not set ACCEPTANYPOLICY to true and ACCEPTEDPOLICIES at the same time");
        } else if (!acceptAnyPolicy && acceptedPoliciesValue == null) {
            configErrors.add("Must specify either ACCEPTEDPOLICIES or ACCEPTANYPOLICY true");
        }

        final String legacyEncodingValue = config.getProperty("LEGACYENCODING", Boolean.FALSE.toString());

        if (Boolean.TRUE.toString().equalsIgnoreCase(legacyEncodingValue)) {
            legacyEncoding = true;
        } else if (Boolean.FALSE.toString().equalsIgnoreCase(legacyEncodingValue)) {
            legacyEncoding = false;
        } else {
            configErrors.add("Illegal value for LEGACYENCODING: " + legacyEncodingValue);
        }

        // Print the errors for troubleshooting
        if (!configErrors.isEmpty()) {
            LOG.info("Configuration errors for worker " + workerId + ": \n" + configErrors);
        }
    }

    private ASN1ObjectIdentifier getCertificateDigestAlgorithmFromString(final String digestAlg) {
        switch (digestAlg) {
            case "SHA1":
            case "SHA-1":
                return TSPAlgorithms.SHA1;
            case "SHA224":
            case "SHA-224":
                return TSPAlgorithms.SHA224;
            case "SHA256":
            case "SHA-256":
                return TSPAlgorithms.SHA256;
            case "SHA384":
            case "SHA-384":
                return TSPAlgorithms.SHA384;
            case "SHA512":
            case "SHA-512":
                return TSPAlgorithms.SHA512;
            default:
                configErrors.add("Unsupported certificate digest algorithm: " + digestAlg);
                return null;
        }
    }

    /**
     * The main method performing the actual timestamp operation.
     * Expects the signRequest to be a GenericSignRequest containing a
     * TimeStampRequest
     *
     * @param signRequest sign request.
     * @param requestContext sign request's context.
     * @return the sign response
     * @throws IllegalRequestException illegal/improper request.
     * @throws CryptoTokenOfflineException crypto token offline.
     * @throws SignServerException general exception
     * @see org.signserver.server.IProcessable#processData(Request, RequestContext)
     */
    @Override
    public Response processData(final Request signRequest,
            final RequestContext requestContext) throws
            IllegalRequestException,
            CryptoTokenOfflineException,
            SignServerException {

        // Check that the request contains a valid TimeStampRequest object.
        if (!(signRequest instanceof SignatureRequest)) {
            throw new IllegalRequestException("Received request wasn't an expected GenericSignRequest. ");
        }
        final SignatureRequest sReq = (SignatureRequest) signRequest;

        // Log values
        final LogMap logMap = LogMap.getInstance(requestContext);

        if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }

        if (!validChain) {
            LOG.error("Certificate chain not correctly configured");
            throw new CryptoTokenOfflineException("Certificate chain not correctly configured");
        }

        final ITimeSource timeSrc = getTimeSource();
        if (LOG.isDebugEnabled()) {
            LOG.debug("TimeSource: " + timeSrc.getClass().getName());
        }
        final Date date = timeSrc.getGenTime(requestContext);
        final BigInteger serialNumber = getSerialNumber();

        // Log values
        logMap.put(ITimeStampLogger.LOG_TSA_TIME,
                new Loggable() {
            @Override
            public String toString() {
                           return date == null ?
                                  null : String.valueOf(date.getTime());
            }
        });
        logMap.put(ITimeStampLogger.LOG_TSA_SERIALNUMBER,
                new Loggable() {
            @Override
            public String toString() {
                return serialNumber.toString(16);

            }
        });
        logMap.put(ITimeStampLogger.LOG_TSA_TIMESOURCE,
                new Loggable() {
            @Override
            public String toString() {
                return timeSrc.getClass().getSimpleName();
            }
        });

        final WritableData responseData = sReq.getResponseData();
        Certificate cert;
        ICryptoInstance crypto = null;
        try (OutputStream out = responseData.getAsInMemoryOutputStream()) {
            crypto = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, signRequest, requestContext);
            final byte[] requestBytes = sReq.getRequestData().getAsByteArray();

            if (ArrayUtils.isEmpty(requestBytes)) {
                LOG.error("Request must contain data");
                throw new IllegalRequestException("Request must contain data");
            }

            logMap.put(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_ENCODED,
                        new Loggable() {
                            @Override
                            public String toString() {
                                return new String(Base64.encode(requestBytes, false));
                            }
                        }
            );

            TimeStampRequest timeStampRequest = null;
            try {
                timeStampRequest = new TimeStampRequest(requestBytes);

                final TimeStampRequest parsedRequest = timeStampRequest;

                // Log values for timestamp request
                logMap.put(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_CERTREQ,
                        new Loggable() {
                            @Override
                            public String toString() {
                                return String.valueOf(parsedRequest.getCertReq());
                            }
                        }
                );
                logMap.put(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_CRITEXTOIDS,
                        new Loggable() {
                            @Override
                            public String toString() {
                                return String.valueOf(parsedRequest.getCriticalExtensionOIDs());
                            }
                        }
                );

                logMap.put(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_NONCRITEXTOIDS,
                        new Loggable() {
                            @Override
                            public String toString() {
                                return String.valueOf(parsedRequest.getNonCriticalExtensionOIDs());
                            }
                        }
                );
                logMap.put(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_NONCE,
                        new Loggable() {
                            @Override
                            public String toString() {
                                return String.valueOf(parsedRequest.getNonce());
                            }
                        }
                );
                logMap.put(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_VERSION,
                        new Loggable() {
                            @Override
                            public String toString() {
                                return String.valueOf(parsedRequest.getVersion());
                            }
                        }
                );
                logMap.put(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_MESSAGEIMPRINTALGOID,
                        new Loggable() {
                            @Override
                            public String toString() {
                                return parsedRequest.getMessageImprintAlgOID().getId();
                            }
                        }
                );
                logMap.put(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_MESSAGEIMPRINTDIGEST,
                        new Loggable() {
                            @Override
                            public String toString() {
                                return new String(Base64.encode(
                                        parsedRequest.getMessageImprintDigest(),
                                        false));
                            }
                        }
                );
            } catch (IOException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unable to parse request", ex);
                }
            }

            // Create the response
            TimeStampResponse timeStampResponse;
            if (timeStampRequest == null) {
                // Generate failure response
                final TimeStampResponseGenerator timeStampResponseGen = getTimeStampResponseGenerator(null);
                timeStampResponse = timeStampResponseGen.generateRejectedResponse(new TSPValidationException("The request could not be parsed.", PKIFailureInfo.badDataFormat));
            } else if (date == null) {
                // Generate failure response
                final TimeStampResponseGenerator timeStampResponseGen = getTimeStampResponseGenerator(null);
                timeStampResponse = timeStampResponseGen.generateRejectedResponse(new TSPValidationException("The time source is not available.", PKIFailureInfo.timeNotAvailable));
            } else {
                try {
                    // Validate according to policy
                    timeStampRequest.validate(getAcceptedAlgorithms(), acceptAnyPolicy ? null : this.getAcceptedPolicies(), getAcceptedExtensions());

                    // Create the generators
                    final TimeStampTokenGenerator timeStampTokenGen = getTimeStampTokenGenerator(crypto, timeStampRequest, logMap);
                    final TimeStampResponseGenerator timeStampResponseGen = getTimeStampResponseGenerator(timeStampTokenGen);
                    final Extensions additionalExtensions = getAdditionalExtensions(signRequest, requestContext);

                    // Generate the response
                    timeStampResponse = timeStampResponseGen.generateGrantedResponse(timeStampRequest,
                                    serialNumber, date,
                                    includeStatusString ? "Operation Okay" : null,
                                    additionalExtensions);
                } catch (TSPException e) {
                    // Generate failure response
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Got exception generating response: ", e);
                    }
                    final TimeStampResponseGenerator timeStampResponseGen = getTimeStampResponseGenerator(null);
                    timeStampResponse = timeStampResponseGen.generateRejectedResponse(e);
                }
            }

            final TimeStampToken token = timeStampResponse.getTimeStampToken();
            final byte[] signedBytes = legacyEncoding ? timeStampResponse.getEncoded(ASN1Encoding.DL) : timeStampResponse.getEncoded();
            out.write(signedBytes);
            cert = getSigningCertificate(crypto);

            // validate the timestamp token signature before sending response
            // token should not be null if generated till now
            if (verifyTokenSignature && token != null) {
                verifySignature(token, cert);
            }

            final TimeStampResponse tspResponse = timeStampResponse;

            // Log values for timestamp response
            if (LOG.isDebugEnabled()) {
                LOG.debug("Time stamp response status: "
                        + timeStampResponse.getStatus() + ": "
                        + timeStampResponse.getStatusString());
            }
            logMap.put(ITimeStampLogger.LOG_TSA_PKISTATUS,
                    new Loggable() {
                @Override
                public String toString() {
                    return String.valueOf(tspResponse.getStatus());
                }
            });

            if (timeStampResponse.getFailInfo() != null) {
                logMap.put(ITimeStampLogger.LOG_TSA_PKIFAILUREINFO,
                        new Loggable() {
                    @Override
                    public String toString() {
                        return String.valueOf(tspResponse.getFailInfo().intValue());
                    }
                });
            }
            logMap.put(ITimeStampLogger.LOG_TSA_TIMESTAMPRESPONSE_ENCODED,
                    new Loggable() {
                @Override
                public String toString() {
                    return new String(Base64.encode(signedBytes, false));
                }
            });
            logMap.put(ITimeStampLogger.LOG_TSA_PKISTATUS_STRING,
                    new Loggable() {
                @Override
                public String toString() {
                    return tspResponse.getStatusString();
                }
            });

            final String archiveId;
            if (token == null) {
                archiveId = serialNumber.toString(16);
            } else {
                archiveId = token.getTimeStampInfo().getSerialNumber()
                        .toString(16);
            }

            final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST, REQUEST_CONTENT_TYPE, sReq.getRequestData(), archiveId),
                    new DefaultArchivable(Archivable.TYPE_RESPONSE, RESPONSE_CONTENT_TYPE, responseData.toReadableData(), archiveId)
            );

            // Put in log values
            if (date == null) {
                logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION, "timeSourceNotAvailable");
            }

            // We were able to fulfill the request so the worker session bean
            // can go on and charge the client
            if (timeStampResponse.getStatus() == PKIStatus.GRANTED) {
                // The client can be charged for the request
                requestContext.setRequestFulfilledByWorker(true);
            } else {
                logMap.put(IWorkerLogger.LOG_PROCESS_SUCCESS, false);
            }

            return new SignatureResponse(sReq.getRequestID(),
                    responseData,
                    cert,
                    archiveId,
                    archivables,
                    RESPONSE_CONTENT_TYPE);

        } catch (InvalidAlgorithmParameterException e) {
            final IllegalRequestException exception =
                    new IllegalRequestException(
                            "InvalidAlgorithmParameterException: " + e.getMessage(), e);
            LOG.error("InvalidAlgorithmParameterException: ", e);
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
                    new ExceptionLoggable(exception));
            throw exception;
        } catch (NoSuchAlgorithmException e) {
            final IllegalRequestException exception =
                    new IllegalRequestException(
                            "NoSuchAlgorithmException: " + e.getMessage(), e);
            LOG.error("NoSuchAlgorithmException: ", e);
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
                    new ExceptionLoggable(exception));
            throw exception;
        } catch (NoSuchProviderException e) {
            final IllegalRequestException exception =
                    new IllegalRequestException(
                            "NoSuchProviderException: " + e.getMessage(), e);
            LOG.error("NoSuchProviderException: ", e);
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
                    new ExceptionLoggable(exception));
            throw exception;
        } catch (CertStoreException e) {
            final IllegalRequestException exception =
                    new IllegalRequestException("CertStoreException: "
                            + e.getMessage(), e);
            LOG.error("CertStoreException: ", e);
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
                    new ExceptionLoggable(exception));
            throw exception;
        } catch (IOException e) {
            final IllegalRequestException exception =
                    new IllegalRequestException(
                            "IOException: " + e.getMessage(), e);
            LOG.error("IOException: ", e);
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
                    new ExceptionLoggable(exception));
            throw exception;
        } catch (TSPException e) {
            final IllegalRequestException exception =
                    new IllegalRequestException(e.getMessage(), e);
            LOG.error("TSPException: ", e);
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
                    new ExceptionLoggable(exception));
            throw exception;
        } catch (OperatorCreationException e) {
        	final SignServerException exception =
        			new SignServerException(e.getMessage(), e);
            LOG.error("OperatorCreationException: ", e);
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
                    new ExceptionLoggable(exception));
            throw exception;
        } finally {
            releaseCryptoInstance(crypto, requestContext);
        }
    }

    private void verifySignature(TimeStampToken token, Certificate signerCert) throws SignServerException {
        final SignerInformationVerifier infoVerifier;
        try {
            infoVerifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build((X509Certificate) signerCert);
            token.validate(infoVerifier);
        } catch (TSPValidationException ex) {
            LOG.error("Token validation failed", ex);
            throw new SignServerException("Token validation failed: " + ex.getMessage(), ex);
        } catch (OperatorCreationException | TSPException ex) {
            LOG.error(ex.getMessage(), ex);
            throw new SignServerException(ex.getMessage(), ex);
        }
    }

    /**
     * @return a time source interface expected to provide accurate time
     */
    private ITimeSource getTimeSource() throws SignServerException {
        if (timeSource == null) {
            String classpath = null;
            try {
                classpath
                        = this.config.getProperty(TIMESOURCE, DEFAULT_TIMESOURCE).trim();

                final Class<?> implClass = Class.forName(classpath);
                final Object obj = implClass.getDeclaredConstructor().newInstance();
                timeSource = (ITimeSource) obj;
                timeSource.init(config.getProperties());

            } catch (ClassNotFoundException e) {
                throw new SignServerException("Class not found" + " \"" + classpath + "\"", e);
            } catch (IllegalAccessException iae) {
                throw new SignServerException("Illegal access", iae);
            } catch (NoSuchMethodException | InvocationTargetException | InstantiationException ie) {
                throw new SignServerException("Instantiation error", ie);
            }
        }

        return timeSource;
    }

    @SuppressWarnings("unchecked")
    private Set<ASN1ObjectIdentifier> getAcceptedAlgorithms() {
        if (acceptedAlgorithms == null) {
            final String nonParsedAcceptedAlgorithms =
                    this.config.getProperty(ACCEPTEDALGORITHMS, DEFAULT_NULL);
            if (nonParsedAcceptedAlgorithms == null) {
                acceptedAlgorithms = TSPAlgorithms.ALLOWED;
            } else {
                final String[] subStrings =
                        nonParsedAcceptedAlgorithms.split(";");
                if (subStrings.length > 0) {
                    acceptedAlgorithms = new HashSet<>();
                    for (String subString : subStrings) {
                        final ASN1ObjectIdentifier acceptAlg = ACCEPTED_ALGORITHMS_MAP.get(subString);
                        if (acceptAlg != null) {
                            acceptedAlgorithms.add(acceptAlg);
                        } else {
                            LOG.error("Error, signer " + workerId
                                    + " configured with incompatible acceptable algorithm : " + subString);
                        }
                    }
                }
            }
        }

        return acceptedAlgorithms;
    }

    private Set<String> getAcceptedPolicies() {
        if (acceptedPolicies == null) {
            final String nonParsedAcceptedPolicies =
                    this.config.getPropertyThatCouldBeEmpty(ACCEPTEDPOLICIES);
            acceptedPolicies = makeSetOfProperty(nonParsedAcceptedPolicies);
        }

        return acceptedPolicies;

    }

    private Set<String> getAcceptedExtensions() {
        if (acceptedExtensions == null) {
            final String nonParsedAcceptedExtensions =
                    this.config.getProperty(ACCEPTEDEXTENSIONS, DEFAULT_NULL);
            acceptedExtensions = makeSetOfProperty(nonParsedAcceptedExtensions);
        }

        return acceptedExtensions;
    }

    /**
     * Help method taking a string and creating a java.util.Set of the
     * strings using ';' as a delimiter.
     * If null is used as and argument then will null be returned by the method.
     * @param nonParsedProperty Semicolon separated strings
     * @return Set of Strings
     */
    private Set<String> makeSetOfProperty(final String nonParsedProperty) {
        Set<String> retval = new HashSet<>();
        if (nonParsedProperty != null) {
            final String[] subStrings = nonParsedProperty.split(";");
            for (String oid : subStrings) {
                oid = oid.trim();
                if (!oid.isEmpty()) {
                    retval.add(oid);
                }
            }
        }
        return retval;
    }

    private TimeStampTokenGenerator getTimeStampTokenGenerator(
            final ICryptoInstance crypto,
            final TimeStampRequest timeStampRequest,
            final LogMap logMap)
            throws
            IllegalRequestException,
            CryptoTokenOfflineException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertStoreException,
            OperatorCreationException {

        TimeStampTokenGenerator timeStampTokenGen;
        try {
            final ASN1ObjectIdentifier tSAPolicyOID;

            if (timeStampRequest.getReqPolicy() != null) {
                tSAPolicyOID = timeStampRequest.getReqPolicy();
            } else {
                tSAPolicyOID = defaultTSAPolicyOID;
            }
            logMap.put(ITimeStampLogger.LOG_TSA_POLICYID,
                    new Loggable() {
                @Override
                public String toString() {
                    return tSAPolicyOID.getId();
                }
            });

            final X509Certificate signingCert
                    = (X509Certificate) getSigningCertificate(crypto);
            if (signingCert == null) {
                throw new CryptoTokenOfflineException(
                        "No certificate for this signer");
            }

            DigestCalculatorProvider calcProv = new BcDigestCalculatorProvider();
            DigestCalculator calc = calcProv.get(new AlgorithmIdentifier(certificateDigestAlgorithm));

            ContentSigner cs =
            		new JcaContentSignerBuilder(signatureAlgorithm).setProvider(crypto.getProvider()).build(crypto.getPrivateKey());
            JcaSignerInfoGeneratorBuilder sigb = new JcaSignerInfoGeneratorBuilder(calcProv);
            X509CertificateHolder certHolder = new X509CertificateHolder(signingCert.getEncoded());

            // set signed attribute table generator based on property
            final Collection<ASN1ObjectIdentifier> attributesToRemove = new ArrayList<>();
            if (!includeSigningTimeAttribute) {
                attributesToRemove.add(CMSAttributes.signingTime);
            }
            if (!includeCmsProtectAlgorithmAttribute) {
                attributesToRemove.add(CMSAttributes.cmsAlgorithmProtect);
            }
            sigb.setSignedAttributeGenerator(
                    new FilteredSignedAttributeTableGenerator(attributesToRemove));

            SignerInfoGenerator sig = sigb.build(cs, certHolder);

            timeStampTokenGen = new TimeStampTokenGenerator(sig, calc, tSAPolicyOID, includeCertIDIssuerSerial);

            if (config.getProperty(ACCURACYMICROS, DEFAULT_NULL) != null) {
                timeStampTokenGen.setAccuracyMicros(Integer.parseInt(
                        config.getProperty(ACCURACYMICROS)));
            }

            if (config.getProperty(ACCURACYMILLIS, DEFAULT_NULL) != null) {
                timeStampTokenGen.setAccuracyMillis(Integer.parseInt(
                        config.getProperty(ACCURACYMILLIS)));
            }

            if (config.getProperty(ACCURACYSECONDS, DEFAULT_NULL) != null) {
                timeStampTokenGen.setAccuracySeconds(Integer.parseInt(
                        config.getProperty(ACCURACYSECONDS)));
            }

            timeStampTokenGen.setOrdering(ordering);

            if (tsaName != null) {
                final X500Name x500Name = new X500Name(tsaName);
                timeStampTokenGen.setTSA(new GeneralName(x500Name));
            } else if (tsaNameFromCert) {
                final X500Name x500Name = new JcaX509CertificateHolder(signingCert).getSubject();
                timeStampTokenGen.setTSA(new GeneralName(x500Name));
            }

            timeStampTokenGen.addCertificates(getCertStoreWithChain(signingCert, getSigningCertificateChain(crypto)));

        } catch (IllegalArgumentException e) {
            LOG.error("IllegalArgumentException: ", e);
            throw new IllegalRequestException(e.getMessage());
        } catch (TSPException e) {
            LOG.error("TSPException: ", e);
            throw new IllegalRequestException(e.getMessage());
        } catch (CertificateEncodingException e) {
            LOG.error("CertificateEncodingException: ", e);
            throw new IllegalRequestException(e.getMessage());
        } catch (IOException e) {
            LOG.error("IOException: ", e);
            throw new IllegalRequestException(e.getMessage());
        }

        return timeStampTokenGen;
    }

    private TimeStampResponseGenerator getTimeStampResponseGenerator(
            TimeStampTokenGenerator timeStampTokenGen) {

        return new TimeStampResponseGenerator(timeStampTokenGen,
                this.getAcceptedAlgorithms(),
                acceptAnyPolicy ? null : this.getAcceptedPolicies(),
                this.getAcceptedExtensions());
    }

    /**
     * Help method that generates a serial number using SecureRandom.
     * Uses the configured length of the signer. This is public to allow using directly from
     * unit test.
     *
     * @return Random serial number
     * @throws SignServerException If the maximum serial number length is outside the allowed range
     */
    public BigInteger getSerialNumber() throws SignServerException {
        BigInteger serialNumber = null;

        if (maxSerialNumberLength < MIN_ALLOWED_MAXSERIALNUMBERLENGTH
                || maxSerialNumberLength > MAX_ALLOWED_MAXSERIALNUMBERLENGTH) {
            throw new SignServerException("Maximum serial number length is not in allowed range");
        }

        try {
            serialNumber = getSerno(maxSerialNumberLength);
        } catch (Exception e) {
            LOG.error("Error initiating Serial Number generator, SEVERE ERROR.",
                    e);
        }
        return serialNumber;
    }

    /**
     * Generates a number of serial number bytes. The number returned should
     * be a positive number.
     *
     * @param maxLength the maximum number of octects of the generated serial number
     * @return a BigInteger with a new random serial number.
     */
    public BigInteger getSerno(int maxLength) {
        if (random == null) {
            try {
                random = SecureRandom.getInstance(ALGORITHM);
            } catch (NoSuchAlgorithmException e) {
                LOG.error(e);
            }
        }

        final byte[] serNoBytes = new byte[maxLength];
        random.nextBytes(serNoBytes);

        return new BigInteger(serNoBytes).abs();
    }

    /**
     * @return True if each certificate in the certificate chain can be verified
     * by the next certificate (if any). This does not check that the last
     * certificate is a trusted certificate as the root certificate is normally
     * not included.
     */
    private boolean validateChain(final IServices services) {
        boolean result = true;
        try {
            final List<Certificate> signingCertificateChain =
                    getSigningCertificateChain(services);
            if (signingCertificateChain != null) {
                for (int i = 0; i < signingCertificateChain.size(); i++) {
                    Certificate subject = signingCertificateChain.get(i);

                    // If we have the issuer we can validate the certificate
                    if (signingCertificateChain.size() > i + 1) {
                        Certificate issuer = signingCertificateChain.get(i + 1);
                        try {
                            subject.verify(issuer.getPublicKey(), "BC");
                        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException ex) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Certificate could not be verified: " + ex.getMessage() + ": " + subject);
                            }
                            result = false;
                        }
                    }
                }
            } else {
                // This would be a bug
                LOG.error("Certificate chain was not an list!");
                result = false;
            }
        } catch (CryptoTokenOfflineException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unable to get signer certificate or chain: " + ex.getMessage());
            }
            result = false;
        }
        return result;
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        final List<String> result = new LinkedList<>();
        result.addAll(super.getFatalErrors(services));
        result.addAll(configErrors);

        try {
            // Check signer certificate chain if required
            if (!validChain) {
                result.add("Not strictly valid chain and " + REQUIREVALIDCHAIN + " specified");
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signer " + workerId + ": " + REQUIREVALIDCHAIN + " specified but the chain was not found valid");
                }
            }

            // Check if certificate has the required EKU
            final Certificate certificate = getSigningCertificate(services);
            result.addAll(checkTimeStampCertificate(certificate));
        } catch (CryptoTokenOfflineException ex) {
            if (isCryptoTokenActive(services)) {
                result.add("No signer certificate available");
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Signer " + workerId + ": Could not get signer certificate: " + ex.getMessage());
            }
        }

        // check time source
        final RequestContext context = new RequestContext(true);
        context.setServices(services);
        try {
            if (timeSource == null || timeSource.getGenTime(context) == null) {
                result.add("Time source not available");
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signer " + workerId + ": time source not available");
                }
            }
        } catch (SignServerException ex) {
            result.add("Time source is misconfigured: " + ex.getMessage());
        }

        return result;
    }

    /**
     * Get additional time stamp extensions.
     *
     * @param request Signing request
     * @param context Request context
     * @return An Extensions object, or null if no additional extensions
     *         should be included
     * @throws java.io.IOException IO exception
     */
    protected Extensions getAdditionalExtensions(Request request,
            RequestContext context)
            throws IOException {
        return null;
    }

    @Override
    public WorkerStatusInfo getStatus(List<String> additionalFatalErrors, IServices services) {
        final WorkerStatusInfo status =
                super.getStatus(additionalFatalErrors, services);

        if (timeSource != null) {
            status.getBriefEntries().addAll(timeSource.getStatusBriefEntries());
            status.getCompleteEntries().addAll(timeSource.getStatusCompleteEntries());
        }

        return status;
    }

    @Override
    public List<String> getCertificateIssues(List<Certificate> certificateChain) {
        final List<String> results = super.getCertificateIssues(certificateChain);
        if (!certificateChain.isEmpty()) {
            results.addAll(checkTimeStampCertificate(certificateChain.get(0)));
        }
        return results;
    }

    private List<String> checkTimeStampCertificate(Certificate certificate) {
        ArrayList<String> result = new ArrayList<>();
        try {
            if (certificate instanceof X509Certificate) {
                final X509Certificate cert = (X509Certificate) certificate;
                final List<String> ekus = cert.getExtendedKeyUsage();

                if (ekus == null
                        || !ekus.contains(KeyPurposeId.id_kp_timeStamping.getId())) {
                    result.add("Missing extended key usage timeStamping");
                }

                if (cert.getCriticalExtensionOIDs() == null
                        || !cert.getCriticalExtensionOIDs().contains(Extension.extendedKeyUsage.getId())) {
                    result.add("The extended key usage extension must be present and marked as critical");
                }
                // if extended key usage contains timeStamping and also other
                // usages
                if (ekus != null
                        && ekus.contains(KeyPurposeId.id_kp_timeStamping.getId())
                        && ekus.size() > 1) {
                    result.add("No other extended key usages than timeStamping is allowed");
                }
            } else {
                result.add("Unsupported certificate type");
            }
        } catch (CertificateParsingException ex) {
            result.add("Unable to parse certificate");
            if (LOG.isDebugEnabled()) {
                LOG.debug("Signer " + workerId + ": Unable to parse certificate: " + ex.getMessage());
            }
        }
        return result;
    }

}
