/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.apk.signer;

import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.MinSdkVersionException;
import com.android.apksig.util.DataSources;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.zip.ZipException;
import javax.persistence.EntityManager;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.util.CertTools;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.SignServerException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerConfig;
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
import org.signserver.module.apk.common.ApkUtils;
import org.signserver.server.data.impl.UploadUtil;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;
import org.signserver.server.signers.BaseSigner;

/**
 * Signer for APK packages.
 * 
 * @author Marcus Lundblad
 * @author Markus Kilås
 * @version $Id$
 */
public class ApkSigner extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ApkSigner.class);

    // Worker properties

    /** If the request digest should be created and logged. */
    public static final String DO_LOGREQUEST_DIGEST = "DO_LOGREQUEST_DIGEST";

    /** If the response digest should be created and logged. */
    public static final String DO_LOGRESPONSE_DIGEST = "DO_LOGRESPONSE_DIGEST";

    /** Algorithm for the request digest put in the log. */
    public static final String LOGREQUEST_DIGESTALGORITHM_PROPERTY = "LOGREQUEST_DIGESTALGORITHM";

    /** Algorithm for the request digest put in the log. */
    public static final String LOGRESPONSE_DIGESTALGORITHM_PROPERTY = "LOGRESPONSE_DIGESTALGORITHM";

    /** Create signatures for the different APK signature versions */
    public static final String V1_SIGNATURE = "V1_SIGNATURE";
    public static final String V2_SIGNATURE = "V2_SIGNATURE";
    public static final String V3_SIGNATURE = "V3_SIGNATURE";
    
    /** SDK versions */
    public static final String MIN_SDK_VERSION = "MIN_SDK_VERSION";
    public static final String MAX_SDK_VERSION = "MAX_SDK_VERSION";

    public static final String DEBUGGABLE_APK_PERMITTED = "DEBUGGABLE_APK_PERMITTED";

    public static final String LINEAGE_FILE_CONTENT = "LINEAGE_FILE_CONTENT";

    public static final String V1_SIGNATURE_NAME = "V1_SIGNATURE_NAME";

    /** Client overrides */
    public static final String ALLOW_V1_SIGNATURE_OVERRIDE = "ALLOW_V1_SIGNATURE_OVERRIDE";
    public static final String ALLOW_V2_SIGNATURE_OVERRIDE = "ALLOW_V2_SIGNATURE_OVERRIDE";
    public static final String ALLOW_V3_SIGNATURE_OVERRIDE = "ALLOW_V3_SIGNATURE_OVERRIDE";
    public static final String ALLOW_MIN_SDK_VERSION_OVERRIDE =
            "ALLOW_MIN_SDK_VERSION_OVERRIDE";
    public static final String ALLOW_MAX_SDK_VERSION_OVERRIDE =
            "ALLOW_MAX_SDK_VERSION_OVERRIDE";
    public static final String ALLOW_DEBUGGABLE_APK_PERMITTED_OVERRIDE =
            "ALLOW_DEBUGGABLE_APK_PERMITTED_OVERRIDE";
    public static final String ALLOW_V1_SIGNATURE_NAME_OVERRIDE =
            "ALLOW_V1_SIGNATURE_NAME_OVERRIDE";

    // Default values

    private static final boolean DEFAULT_DO_LOGREQUEST_DIGEST = true;
    private static final String DEFAULT_LOGREQUEST_DIGESTALGORITHM = "SHA256";
    private static final boolean DEFAULT_DO_LOGRESPONSE_DIGEST = true;
    private static final String DEFAULT_LOGRESPONSE_DIGESTALGORITHM = "SHA256";

    // Content types
    private static final String REQUEST_CONTENT_TYPE =
            "application/vnd.android.package-archive";
    private static final String RESPONSE_CONTENT_TYPE =
            "application/vnd.android.package-archive";

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration valuess
    private String logRequestDigestAlgorithm;
    private String logResponseDigestAlgorithm;
    private boolean doLogRequestDigest;
    private boolean doLogResponseDigest;

    private Optional<Boolean> v1Signature = Optional.empty();
    private Optional<Boolean> v2Signature = Optional.empty();
    private Optional<Boolean> v3Signature = Optional.empty();

    private Optional<Integer> minSDKVersion = Optional.empty();
    private Optional<Integer> maxSDKVersion = Optional.empty();

    private boolean debuggableApkPermitted;

    private Optional<SigningCertificateLineage> lineage = Optional.empty();

    private Optional<String> v1SignatureName = Optional.empty();

    private List<String> otherSigners;

    private boolean allowV1SignatureOverride;
    private boolean allowV2SignatureOverride;
    private boolean allowV3SignatureOverride;
    private boolean allowMinSDKVersionOverride;
    private boolean allowMaxSDKVersionOverride;
    private boolean allowDebuggableApkPermittedOverride;
    private boolean allowV1SignatureNameOverride;

    @Override
    @SuppressWarnings("ConvertToStringSwitch")
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Get the log digest algorithms
        logRequestDigestAlgorithm = config.getProperty(LOGREQUEST_DIGESTALGORITHM_PROPERTY, DEFAULT_LOGREQUEST_DIGESTALGORITHM);
        logResponseDigestAlgorithm = config.getProperty(LOGRESPONSE_DIGESTALGORITHM_PROPERTY, DEFAULT_LOGRESPONSE_DIGESTALGORITHM);

        // If the request digest should computed and be logged
        String s = config.getProperty(DO_LOGREQUEST_DIGEST, Boolean.toString(DEFAULT_DO_LOGREQUEST_DIGEST));
        if ("true".equalsIgnoreCase(s)) {
            doLogRequestDigest = true;
        } else if ("false".equalsIgnoreCase(s)) {
            doLogRequestDigest = false;
        } else {
            configErrors.add("Incorrect value for " + DO_LOGREQUEST_DIGEST);
        }

        // If the response digest should computed and be logged
        s = config.getProperty(DO_LOGRESPONSE_DIGEST, Boolean.toString(DEFAULT_DO_LOGRESPONSE_DIGEST));
        if ("true".equalsIgnoreCase(s)) {
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

        // Read properties
        final String v1SignatureValue = config.getProperty(V1_SIGNATURE);
        if (StringUtils.isNotBlank(v1SignatureValue)) {
            if ("true".equals(v1SignatureValue.toLowerCase(Locale.ENGLISH))) {
                v1Signature = Optional.of(true);
            } else if ("false".equals(v1SignatureValue.toLowerCase(Locale.ENGLISH))) {
                v1Signature = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + V1_SIGNATURE + ". Only true, false, or empty is allowed.");
            }
        }

        final String v2SignatureValue = config.getProperty(V2_SIGNATURE);
        if (StringUtils.isNotBlank(v2SignatureValue)) {
            if ("true".equals(v2SignatureValue.toLowerCase(Locale.ENGLISH))) {
                v2Signature = Optional.of(true);
            } else if ("false".equals(v2SignatureValue.toLowerCase(Locale.ENGLISH))) {
                v2Signature = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + V2_SIGNATURE + ". Only true, false, or empty is allowed.");
            }
        }

        final String v3SignatureValue = config.getProperty(V3_SIGNATURE);
        if (StringUtils.isNotBlank(v3SignatureValue)) {
            if ("true".equals(v3SignatureValue.toLowerCase(Locale.ENGLISH))) {
                v3Signature = Optional.of(true);
            } else if ("false".equals(v3SignatureValue.toLowerCase(Locale.ENGLISH))) {
                v3Signature = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + V3_SIGNATURE + ". Only true, false, or empty is allowed.");
            }
        }

        final String minSDKVersionValue = config.getProperty(MIN_SDK_VERSION);
        if (StringUtils.isNotBlank(minSDKVersionValue)) {
            try {
                minSDKVersion = Optional.of(Integer.parseInt(minSDKVersionValue));
                if (minSDKVersion.get() < 1) {
                    configErrors.add("Illegal value for property " + MIN_SDK_VERSION + ": " + minSDKVersionValue);
                }
            } catch (NumberFormatException e) {
                configErrors.add("Illegal value for property " + MIN_SDK_VERSION + ": " + minSDKVersionValue);
            }
        }

        final String maxSDKVersionValue = config.getProperty(MAX_SDK_VERSION);
        if (StringUtils.isNotBlank(maxSDKVersionValue)) {
            try {
                maxSDKVersion = Optional.of(Integer.parseInt(maxSDKVersionValue));
                if (maxSDKVersion.get() < 1) {
                    configErrors.add("Illegal value for property " + MAX_SDK_VERSION + ": " + maxSDKVersionValue);
                }
            } catch (NumberFormatException e) {
                configErrors.add("Illegal value for property " + MAX_SDK_VERSION + ": " + maxSDKVersionValue);
            }
        }

        /* if both MIN_SDK_VERSION and MAX_SDK_VERSION is set, MAX_SDK_VERSION
         * can not be lower than MIN_SDK_VERSION.
         */
        if (minSDKVersion.isPresent() && maxSDKVersion.isPresent() &&
            maxSDKVersion.get() < minSDKVersion.get()) {
            configErrors.add(MAX_SDK_VERSION + " can not be lower than " + MIN_SDK_VERSION);
        }
        
        final String debuggableApkPermittedValue =
                config.getProperty(DEBUGGABLE_APK_PERMITTED);
        if (StringUtils.isNotBlank(debuggableApkPermittedValue)) {
            if ("true".equals(debuggableApkPermittedValue.toLowerCase(Locale.ENGLISH))) {
                debuggableApkPermitted = true;
            } else if ("false".equals(debuggableApkPermittedValue.toLowerCase(Locale.ENGLISH))) {
                debuggableApkPermitted = false;
            } else {
                configErrors.add("Illegal value for property " +
                                 DEBUGGABLE_APK_PERMITTED +
                                 ". Only true or false is allowed.");
            }
        } else {
            debuggableApkPermitted = false;
        }

        final String lineageContentValue = config.getProperty(LINEAGE_FILE_CONTENT);
        if (StringUtils.isNotBlank(lineageContentValue)) {
            try {
                final byte[] data = Base64.decode(lineageContentValue);
                lineage = Optional.of(SigningCertificateLineage.readFromDataSource(DataSources.asDataSource(ByteBuffer.wrap(data))));
            } catch (DecoderException e) {
                configErrors.add("Illegal base64 value for " + LINEAGE_FILE_CONTENT);
            } catch (IOException | IllegalArgumentException e) {
                configErrors.add("Failed to parse lineage: " + e.getMessage());
            }
        }

        final String v1SignatureNameValue = config.getProperty(V1_SIGNATURE_NAME);
        if (StringUtils.isNotBlank(v1SignatureNameValue)) {
            v1SignatureName = Optional.of(v1SignatureNameValue);
        }

        final String otherSignersValue = config.getProperty(WorkerConfig.OTHER_SIGNERS);
        if (StringUtils.isNotBlank(otherSignersValue)) {
            otherSigners = new LinkedList<>();
            for (final String nextSigner : otherSignersValue.split(",")) {
                final String nextSignerTrimmed = nextSigner.trim();

                otherSigners.add(nextSignerTrimmed);
            }
        } else {
            otherSigners = Collections.emptyList();
        }

        final String allowV1SignatureOverrideValue =
                config.getProperty(ALLOW_V1_SIGNATURE_OVERRIDE);
        if (StringUtils.isNotBlank(allowV1SignatureOverrideValue)) {
            if ("true".equals(allowV1SignatureOverrideValue.toLowerCase(Locale.ENGLISH))) {
                allowV1SignatureOverride = true;
            } else if ("false".equals(allowV1SignatureOverrideValue.toLowerCase(Locale.ENGLISH))) {
                allowV1SignatureOverride = false;
            } else {
                configErrors.add("Illegal value for " + ALLOW_V1_SIGNATURE_OVERRIDE +
                                 ": " + allowV1SignatureOverrideValue);
            }
        }

        final String allowV2SignatureOverrideValue =
                config.getProperty(ALLOW_V2_SIGNATURE_OVERRIDE);
        if (StringUtils.isNotBlank(allowV2SignatureOverrideValue)) {
            if ("true".equals(allowV2SignatureOverrideValue.toLowerCase(Locale.ENGLISH))) {
                allowV2SignatureOverride = true;
            } else if ("false".equals(allowV2SignatureOverrideValue.toLowerCase(Locale.ENGLISH))) {
                allowV2SignatureOverride = false;
            } else {
                configErrors.add("Illegal value for " + ALLOW_V2_SIGNATURE_OVERRIDE +
                                 ": " + allowV2SignatureOverrideValue);
            }
        }

        final String allowV3SignatureOverrideValue =
                config.getProperty(ALLOW_V3_SIGNATURE_OVERRIDE);
        if (StringUtils.isNotBlank(allowV3SignatureOverrideValue)) {
            if ("true".equals(allowV3SignatureOverrideValue.toLowerCase(Locale.ENGLISH))) {
                allowV3SignatureOverride = true;
            } else if ("false".equals(allowV3SignatureOverrideValue.toLowerCase(Locale.ENGLISH))) {
                allowV3SignatureOverride = false;
            } else {
                configErrors.add("Illegal value for " + ALLOW_V3_SIGNATURE_OVERRIDE +
                                 ": " + allowV3SignatureOverrideValue);
            }
        }

        final String allowMinSDKVersionOverrideValue =
                config.getProperty(ALLOW_MIN_SDK_VERSION_OVERRIDE);
        if (StringUtils.isNotBlank(allowMinSDKVersionOverrideValue)) {
            if ("true".equals(allowMinSDKVersionOverrideValue.toLowerCase(Locale.ENGLISH))) {
                allowMinSDKVersionOverride = true;
            } else if ("false".equals(allowMinSDKVersionOverrideValue.toLowerCase(Locale.ENGLISH))) {
                allowMinSDKVersionOverride = false;
            } else {
                configErrors.add("Illegal value for " + ALLOW_MIN_SDK_VERSION_OVERRIDE +
                                 ": " + allowMinSDKVersionOverrideValue);
            }
        }

        final String allowMaxSDKVersionOverrideValue =
                config.getProperty(ALLOW_MAX_SDK_VERSION_OVERRIDE);
        if (StringUtils.isNotBlank(allowMaxSDKVersionOverrideValue)) {
            if ("true".equals(allowMaxSDKVersionOverrideValue.toLowerCase(Locale.ENGLISH))) {
                allowMaxSDKVersionOverride = true;
            } else if ("false".equals(allowMaxSDKVersionOverrideValue.toLowerCase(Locale.ENGLISH))) {
                allowMaxSDKVersionOverride = false;
            } else {
                configErrors.add("Illegal value for " + ALLOW_MAX_SDK_VERSION_OVERRIDE +
                                 ": " + allowMaxSDKVersionOverrideValue);
            }
        }

        final String allowDebuggableApkPermittedOverrideValue =
                config.getProperty(ALLOW_DEBUGGABLE_APK_PERMITTED_OVERRIDE);
        if (StringUtils.isNotBlank(allowDebuggableApkPermittedOverrideValue)) {
            if ("true".equals(allowDebuggableApkPermittedOverrideValue.toLowerCase(Locale.ENGLISH))) {
                allowDebuggableApkPermittedOverride = true;
            } else if ("false".equals(allowDebuggableApkPermittedOverrideValue.toLowerCase(Locale.ENGLISH))) {
                allowDebuggableApkPermittedOverride = false;
            } else {
                configErrors.add("Illegal value for " + ALLOW_DEBUGGABLE_APK_PERMITTED_OVERRIDE +
                                 ": " + allowDebuggableApkPermittedOverrideValue);
            }
        }

        final String allowV1SignatureNameOverrideValue =
                config.getProperty(ALLOW_V1_SIGNATURE_NAME_OVERRIDE);
        if (StringUtils.isNotBlank(allowV1SignatureNameOverrideValue)) {
            if ("true".equals(allowV1SignatureNameOverrideValue.toLowerCase(Locale.ENGLISH))) {
                allowV1SignatureNameOverride = true;
            } else if ("false".equals(allowV1SignatureNameOverrideValue.toLowerCase(Locale.ENGLISH))) {
                allowV1SignatureNameOverride = false;
            } else {
                configErrors.add("Illegal value for " + ALLOW_V1_SIGNATURE_NAME_OVERRIDE +
                                 ": " + allowV1SignatureNameOverrideValue);
            }
        }
    }

    @Override
    public Response processData(Request signRequest,
            RequestContext requestContext) throws IllegalRequestException,
        CryptoTokenOfflineException, SignServerException {
        if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }
        if (!(signRequest instanceof SignatureRequest)) {
            throw new IllegalRequestException("Unexpected request type");
        }
        final SignatureRequest sReq = (SignatureRequest) signRequest;

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
        final List<ICryptoInstance> cryptoInstances = new ArrayList<>(5);
        
        File outFile;
        final String archiveId;

        try {
            List<com.android.apksig.ApkSigner.SignerConfig> signerConfigs = new ArrayList<>();
            final Set<String> sfNames = new HashSet<>();
            
            // Get this worker's own crypto instance
            ICryptoInstance ownCryptoInstance = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, signRequest, requestContext);
            cryptoInstances.add(ownCryptoInstance);
            signerConfigs.add(createSignerConfig(ownCryptoInstance, sfNames, requestContext));
            
            // Get crypto instances for the "other signers", this should match the same number as in the OTHER_SIGNERS property
            final List<ICryptoInstance> otherCryptoInstances = acquireCryptoInstancesFromOtherSigners(ICryptoTokenV4.PURPOSE_SIGN, signRequest, logMap, requestContext);
            if (otherCryptoInstances.size() != otherSigners.size()) {
                throw new SignServerException("Not all " + WorkerConfig.OTHER_SIGNERS + " was found and loaded successfully.");
            }
            for (ICryptoInstance cryptoInstance : otherCryptoInstances) {
                cryptoInstances.add(cryptoInstance);
                signerConfigs.add(createSignerConfig(cryptoInstance, sfNames, requestContext));
            }

            outFile = responseData.getAsFile();

            final Optional<Boolean> v1SignatureEnabled =
                    getBooleanOverridableValue(V1_SIGNATURE,
                                               allowV1SignatureOverride,
                                               v1Signature, requestContext);
            final Optional<Boolean> v2SignatureEnabled =
                    getBooleanOverridableValue(V2_SIGNATURE,
                                               allowV2SignatureOverride,
                                               v2Signature, requestContext);
            final Optional<Boolean> v3SignatureEnabled =
                    getBooleanOverridableValue(V3_SIGNATURE,
                                               allowV3SignatureOverride,
                                               v3Signature, requestContext);
            final Optional<Boolean> debuggableApkPermittedEnabled =
                    getBooleanOverridableValue(DEBUGGABLE_APK_PERMITTED,
                                               allowDebuggableApkPermittedOverride,
                                               Optional.of(debuggableApkPermitted),
                                               requestContext);
            final Optional<Integer> minSDKVersionValue =
                    getPositiveIntegerOverridableValue(MIN_SDK_VERSION,
                                                       allowMinSDKVersionOverride,
                                                       minSDKVersion,
                                                       requestContext);
            // Note: this value is not currently used, but we still want
            // to check the client-side provided value, if present so
            // that it is a proper integer
            final Optional<Integer> maxSDKVersionValue =
                    getPositiveIntegerOverridableValue(MAX_SDK_VERSION,
                                                       allowMaxSDKVersionOverride,
                                                       maxSDKVersion,
                                                       requestContext);

            // Implementation
            com.android.apksig.ApkSigner.Builder apkSignerBuilder =
                new com.android.apksig.ApkSigner.Builder(signerConfigs)
                        .setInputApk(data.getAsFile())
                        .setOutputApk(responseData.getAsFile())
                        .setOtherSignersSignaturesPreserved(false);
            if (v1SignatureEnabled.isPresent()) {
                apkSignerBuilder.setV1SigningEnabled(v1SignatureEnabled.get());
            }
            if (v2SignatureEnabled.isPresent()) {
                apkSignerBuilder.setV2SigningEnabled(v2SignatureEnabled.get());
            }
            if (v3SignatureEnabled.isPresent()) {
                apkSignerBuilder.setV3SigningEnabled(v3SignatureEnabled.get());
            }
            if (debuggableApkPermittedEnabled.isPresent()) {
                apkSignerBuilder.setDebuggableApkPermitted(debuggableApkPermittedEnabled.get());
            }
            if (minSDKVersionValue.isPresent()) {
                apkSignerBuilder.setMinSdkVersion(minSDKVersionValue.get());
            }
            if (lineage.isPresent()) {
                apkSignerBuilder.setSigningCertificateLineage(lineage.get());
            }

            com.android.apksig.ApkSigner apkSigner = apkSignerBuilder.build();
            try {
                apkSigner.sign();
            } catch (MinSdkVersionException e) {
                throw new IllegalRequestException(
                        "Failed to determine APK's minimum supported platform version"
                                + ". Use --min-sdk-version to override",
                        e);
            } catch (ApkFormatException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | IllegalStateException ex) {
                throw new SignServerException("apk signing error", ex);
            }

            // TODO: Future optimization: For performance reasons, instead of
            // hashing the document again and use that in the archive id, we
            // should be able to somehow get the already hashed value from the
            // signing implementation or to extract the digest from the
            // SignedData structure
            archiveId = createArchiveId(/*signer.getCachedDigest()*/ new byte[0], (String) requestContext.get(RequestContext.TRANSACTION_ID));

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
            LOG.debug("Parse error", ex);
            throw new IllegalRequestException("Unable to parse ZIP file", ex);
        } catch (IOException ex) {
            LOG.debug("IO error", ex);
            throw new SignServerException(ex.getMessage());
        } catch (UnsupportedCryptoTokenParameter ex) {
            throw new SignServerException("Crypto token parameter(s) was/were unknown or unsupported by the crypto token.", ex);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new SignServerException("Empty list of parameters reported as invalid by crypto token", ex);
        } catch (IllegalArgumentException ex) {
            throw new SignServerException(ex.getLocalizedMessage(), ex);
        } finally {
            for (ICryptoInstance cryptoInstance : cryptoInstances) {
                releaseCryptoInstance(cryptoInstance, requestContext);
            }
        }

        final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST, REQUEST_CONTENT_TYPE, data, archiveId),
                    new DefaultArchivable(Archivable.TYPE_RESPONSE, RESPONSE_CONTENT_TYPE, responseData.toReadableData(), archiveId));

        // The client can be charged for the request
        requestContext.setRequestFulfilledByWorker(true);

        // Return the response
        return new SignatureResponse(sReq.getRequestID(), responseData, null, archiveId, archivables, RESPONSE_CONTENT_TYPE);
    }

    /**
     * Get a boolean override value from request metadata.
     * 
     * @param property Property name
     * @param requestContext Request context
     * @return Optionally the value, if present in the request, otherwise empty
     * @throws IllegalRequestException  If the parameter is present and not
     *                                  a well-formed boolean value
     */
    @SuppressWarnings("ConvertToStringSwitch")
    private Optional<Boolean> getBooleanOverride(final String property,
                                       final RequestContext requestContext)
        throws IllegalRequestException {
        final String value =
                RequestMetadata.getInstance(requestContext).get(property);

        if (StringUtils.isNotBlank(value)) {
            if ("true".equals(value.toLowerCase(Locale.ENGLISH))) {
                return Optional.of(true);
            } else if ("false".equals(value.toLowerCase(Locale.ENGLISH))) {
                return Optional.of(false);
            } else {
                throw new IllegalRequestException("Illegal value for " +
                                                  property + " in request: " +
                                                  value);
            }
        } else {
            return Optional.empty();
        }
    }

    /**
     * Get a positive integer override value from request metadata.
     * 
     * @param property Property name
     * @param requestContext Request context
     * @return Optionally the value, if present in the request, otherwise empty
     * @throws IllegalRequestException  If the parameter is present and not
     *                                  a well-formed integer value
     */
    private Optional<Integer> getPositiveIntegerOverride(final String property,
                                                         final RequestContext requestContext)
            throws IllegalRequestException {
        final String value =
                RequestMetadata.getInstance(requestContext).get(property);

        if (StringUtils.isNotBlank(value)) {
            try {
                final int intValue = Integer.parseInt(value);

                if (intValue < 1) {
                    throw new IllegalRequestException("Illegal value for " +
                                                      property + " in request: " +
                                                      value);
                }
                
                return Optional.of(intValue);
            } catch (NumberFormatException e) {
                throw new IllegalRequestException("Illegal value for " +
                                                  property + " in request: " +
                                                  value);
            }
        } else {
            return Optional.empty();
        }
    }
    
    /**
     * Get a boolean value from the request context, if available, else from
     * a supplied static default value (typically the configured worker property).
     * 
     * @param property Property name
     * @param allowOverride True if the value should be overridable through the context
     * @param defaultValue Default value to use, if supplied and it is not overridden
     * @param requestContext The request context
     * @return Value to use, from the context if overridable and present in the context,
     *         otherwise the default value, or empty
     * @throws IllegalRequestException If attempting to override when not allowed
     *                                 or the value from the context is not well-formed
     */
    private Optional<Boolean> getBooleanOverridableValue(final String property,
                                                         final boolean allowOverride,
                                                         final Optional<Boolean> defaultValue,
                                                         final RequestContext requestContext)
            throws IllegalRequestException {
        final Optional<Boolean> value = getBooleanOverride(property, requestContext);

        if (defaultValue.isPresent()) {
            if (value.isPresent()) {
                if (value.get() && (defaultValue.get() || allowOverride)) {
                    return value;
                } else if (!value.get() && (!defaultValue.get() || allowOverride)) {
                    return value;
                } else {
                    throw new IllegalRequestException("Overriding " + property +
                                                      " in the request is not permitted");
                }
            } else {
                return defaultValue;
            }
        } else {
            if (value.isPresent()) {
                if (allowOverride) {
                    return value;
                } else {
                    throw new IllegalRequestException("Overriding " + property +
                                                      " in the request is not permitted");
                }
            } else {
                return Optional.empty();
            }
        }
    }

    /**
     * Get a positive integer value from the request context, if avaiable, else from
     * a supplied static default value (typically the configured worker property).
     * 
     * @param property Property name
     * @param allowOverride True if the value should be overridable through the context
     * @param defaultValue Default value to use, if supplied and it is not overridden
     * @param requestContext The request context
     * @return Value to use, from the context if overridable and present in the context,
     *         otherwise the default value
     * @throws IllegalRequestException If attempting to override when not allowed
     *                                 or the value from the context is not well-formed
     */
    private Optional<Integer> getPositiveIntegerOverridableValue(
                                        final String property,
                                        final boolean allowOverride,
                                        final Optional<Integer> defaultValue,
                                        final RequestContext requestContext)
            throws IllegalRequestException {
        final Optional<Integer> value =
                    getPositiveIntegerOverride(property, requestContext);

        if (defaultValue.isPresent()) {
            if (value.isPresent()) {
                if (value.get().intValue() == defaultValue.get().intValue() ||
                    allowOverride) {
                    return value;
                } else {
                    throw new IllegalRequestException("Overriding " + property +
                                                      " in the request is not permitted");
                }
            } else {
                return defaultValue;
            }
        } else {
            if (value.isPresent()) {
                if (allowOverride) {
                    return value;
                } else {
                    throw new IllegalRequestException("Overriding " + property +
                                                      " in the request is not permitted");
                }
            } else {
                return Optional.empty();
            }
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

    /**
     * Create the config for the signer given by the crypto instance.
     * @param cryptoInstance to create config for
     * @param sfNames existing v1 signature names
     * @param requestContext
     * @return the signer config
     * @throws SignServerException 
     */
    private com.android.apksig.ApkSigner.SignerConfig createSignerConfig(ICryptoInstance cryptoInstance, Set<String> sfNames, RequestContext requestContext) throws SignServerException {

        // Get certificate chain and signer certificate
        List<Certificate> certs = getSigningCertificateChain(cryptoInstance);
        if (CollectionUtils.isEmpty(certs)) {
            throw new IllegalArgumentException("No certificate chain. This signer needs a certificate.");
        }
        Certificate signerCert = certs.get(0);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SigningCert: " + ((X509Certificate) signerCert).getSubjectDN());
        }

        certs = includedCertificates(certs);
        
        // Get name to use for the signature
        String signatureName;
        final String signatureNameClientValue =
                RequestMetadata.getInstance(requestContext).get(V1_SIGNATURE_NAME);

        if (StringUtils.isNotBlank(signatureNameClientValue) &&
            (v1SignatureName.isPresent() &&
             signatureNameClientValue.equals(v1SignatureName.get()) ||
             allowV1SignatureNameOverride)) {
            signatureName = signatureNameClientValue;
        } else if (v1SignatureName.isPresent()) {
            signatureName = v1SignatureName.get();
        } else {
            // Fallback to use the common name or the whole DN
            final String dn = CertTools.getSubjectDN(signerCert);
            signatureName = CertTools.getPartFromDN(dn, "CN");
            if (signatureName == null) {
                signatureName = dn;
            }
        }
        
        signatureName =
                ApkUtils.createUniqueSignatureFileName(ApkUtils.convertToValidSignatureName(signatureName),
                                                       sfNames);

        return new com.android.apksig.ApkSigner.SignerConfig.Builder(
                signatureName, cryptoInstance.getPrivateKey(),
                ApkUtils.toX509List(certs))
                .build();
    }
}
