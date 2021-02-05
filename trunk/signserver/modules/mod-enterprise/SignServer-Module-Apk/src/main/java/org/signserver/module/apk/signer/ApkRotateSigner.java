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
package org.signserver.module.apk.signer;

import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.SigningCertificateLineage.SignerCapabilities;
import com.android.apksig.internal.util.ByteArrayDataSink;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import javax.persistence.EntityManager;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
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
import static org.signserver.module.apk.signer.ApkSigner.MIN_SDK_VERSION;
import org.signserver.server.log.LogMap;
import org.signserver.server.signers.BaseSigner;

/**
 * APK rotate signer.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ApkRotateSigner extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ApkRotateSigner.class);

    // Content types
    private static final String RESPONSE_CONTENT_TYPE = "application/octet-stream";

    // Worker properties
    public static final String PROPERTY_OLD_SET_INSTALLED_DATA = "OLD_SET_INSTALLED_DATA";
    public static final String PROPERTY_OLD_SET_SHARED_UID = "OLD_SET_SHARED_UID";
    public static final String PROPERTY_OLD_SET_PERMISSION = "OLD_SET_PERMISSION";
    public static final String PROPERTY_OLD_SET_ROLLBACK = "OLD_SET_ROLLBACK";
    public static final String PROPERTY_OLD_SET_AUTH = "OLD_SET_AUTH";
    public static final String PROPERTY_NEW_SET_INSTALLED_DATA = "NEW_SET_INSTALLED_DATA";
    public static final String PROPERTY_NEW_SET_SHARED_UID = "NEW_SET_SHARED_UID";
    public static final String PROPERTY_NEW_SET_PERMISSION = "NEW_SET_PERMISSION";
    public static final String PROPERTY_NEW_SET_ROLLBACK = "NEW_SET_ROLLBACK";
    public static final String PROPERTY_NEW_SET_AUTH = "NEW_SET_AUTH";
    public static final String PROPERTY_MIN_SDK_VERSION = "MIN_SDK_VERSION";
    
    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    private Optional<Boolean> oldSetInstalledData = Optional.empty();
    private Optional<Boolean> oldSetSharedUid = Optional.empty();
    private Optional<Boolean> oldSetPermission = Optional.empty();
    private Optional<Boolean> oldSetRollback = Optional.empty();
    private Optional<Boolean> oldSetAuth = Optional.empty();
    private Optional<Boolean> newSetInstalledData = Optional.empty();
    private Optional<Boolean> newSetSharedUid = Optional.empty();
    private Optional<Boolean> newSetPermission = Optional.empty();
    private Optional<Boolean> newSetRollback = Optional.empty();
    private Optional<Boolean> newSetAuth = Optional.empty();
    private Optional<Integer> minSdkVersion = Optional.empty();
    
    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Read properties
        final String otherSignersValue = config.getProperty(WorkerConfig.OTHER_SIGNERS);
        if (StringUtils.isNotBlank(otherSignersValue)) {
            final String[] otherSigners = otherSignersValue.split(",");
            if (otherSigners.length != 2) {
                configErrors.add(WorkerConfig.OTHER_SIGNERS + " should contain two signers (old and new).");
            }
        } else {
            configErrors.add("Must specify " + WorkerConfig.OTHER_SIGNERS + ".");
        }

        final String oldSetInstalledDataValue = config.getProperty(PROPERTY_OLD_SET_INSTALLED_DATA);
        if (StringUtils.isNotBlank(oldSetInstalledDataValue)) {
            if ("true".equals(oldSetInstalledDataValue.toLowerCase(Locale.ENGLISH))) {
                oldSetInstalledData = Optional.of(true);
            } else if ("false".equals(oldSetInstalledDataValue.toLowerCase(Locale.ENGLISH))) {
                oldSetInstalledData = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + PROPERTY_OLD_SET_INSTALLED_DATA + ". Only true, false, or empty is allowed.");
            }
        }

        final String oldSetSharedUidValue = config.getProperty(PROPERTY_OLD_SET_SHARED_UID);
        if (StringUtils.isNotBlank(oldSetSharedUidValue)) {
            if ("true".equals(oldSetSharedUidValue.toLowerCase(Locale.ENGLISH))) {
                oldSetSharedUid = Optional.of(true);
            } else if ("false".equals(oldSetSharedUidValue.toLowerCase(Locale.ENGLISH))) {
                oldSetSharedUid = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + PROPERTY_OLD_SET_SHARED_UID + ". Only true, false, or empty is allowed.");
            }
        }

        final String oldSetPermissionValue = config.getProperty(PROPERTY_OLD_SET_PERMISSION);
        if (StringUtils.isNotBlank(oldSetPermissionValue)) {
            if ("true".equals(oldSetPermissionValue.toLowerCase(Locale.ENGLISH))) {
                oldSetPermission = Optional.of(true);
            } else if ("false".equals(oldSetPermissionValue.toLowerCase(Locale.ENGLISH))) {
                oldSetPermission = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + PROPERTY_OLD_SET_PERMISSION + ". Only true, false, or empty is allowed.");
            }
        }

        final String oldSetRollbackValue = config.getProperty(PROPERTY_OLD_SET_ROLLBACK);
        if (StringUtils.isNotBlank(oldSetRollbackValue)) {
            if ("true".equals(oldSetRollbackValue.toLowerCase(Locale.ENGLISH))) {
                oldSetRollback = Optional.of(true);
            } else if ("false".equals(oldSetRollbackValue.toLowerCase(Locale.ENGLISH))) {
                oldSetRollback = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + PROPERTY_OLD_SET_ROLLBACK + ". Only true, false, or empty is allowed.");
            }
        }

        final String oldSetAuthValue = config.getProperty(PROPERTY_OLD_SET_AUTH);
        if (StringUtils.isNotBlank(oldSetAuthValue)) {
            if ("true".equals(oldSetAuthValue.toLowerCase(Locale.ENGLISH))) {
                oldSetAuth = Optional.of(true);
            } else if ("false".equals(oldSetAuthValue.toLowerCase(Locale.ENGLISH))) {
                oldSetAuth = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + PROPERTY_OLD_SET_AUTH + ". Only true, false, or empty is allowed.");
            }
        }

        final String newSetInstalledDataValue = config.getProperty(PROPERTY_NEW_SET_INSTALLED_DATA);
        if (StringUtils.isNotBlank(newSetInstalledDataValue)) {
            if ("true".equals(newSetInstalledDataValue.toLowerCase(Locale.ENGLISH))) {
                newSetInstalledData = Optional.of(true);
            } else if ("false".equals(newSetInstalledDataValue.toLowerCase(Locale.ENGLISH))) {
                newSetInstalledData = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + PROPERTY_NEW_SET_INSTALLED_DATA + ". Only true, false, or empty is allowed.");
            }
        }

        final String newSetSharedUidValue = config.getProperty(PROPERTY_NEW_SET_SHARED_UID);
        if (StringUtils.isNotBlank(newSetSharedUidValue)) {
            if ("true".equals(newSetSharedUidValue.toLowerCase(Locale.ENGLISH))) {
                newSetSharedUid = Optional.of(true);
            } else if ("false".equals(newSetSharedUidValue.toLowerCase(Locale.ENGLISH))) {
                newSetSharedUid = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + PROPERTY_NEW_SET_SHARED_UID + ". Only true, false, or empty is allowed.");
            }
        }

        final String newSetPermissionValue = config.getProperty(PROPERTY_NEW_SET_PERMISSION);
        if (StringUtils.isNotBlank(newSetPermissionValue)) {
            if ("true".equals(newSetPermissionValue.toLowerCase(Locale.ENGLISH))) {
                newSetPermission = Optional.of(true);
            } else if ("false".equals(newSetPermissionValue.toLowerCase(Locale.ENGLISH))) {
                newSetPermission = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + PROPERTY_NEW_SET_PERMISSION + ". Only true, false, or empty is allowed.");
            }
        }

        final String newSetRollbackValue = config.getProperty(PROPERTY_NEW_SET_ROLLBACK);
        if (StringUtils.isNotBlank(newSetRollbackValue)) {
            if ("true".equals(newSetRollbackValue.toLowerCase(Locale.ENGLISH))) {
                newSetRollback = Optional.of(true);
            } else if ("false".equals(newSetRollbackValue.toLowerCase(Locale.ENGLISH))) {
                newSetRollback = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + PROPERTY_NEW_SET_ROLLBACK + ". Only true, false, or empty is allowed.");
            }
        }

        final String newSetAuthValue = config.getProperty(PROPERTY_NEW_SET_AUTH);
        if (StringUtils.isNotBlank(newSetAuthValue)) {
            if ("true".equals(newSetAuthValue.toLowerCase(Locale.ENGLISH))) {
                newSetAuth = Optional.of(true);
            } else if ("false".equals(newSetAuthValue.toLowerCase(Locale.ENGLISH))) {
                newSetAuth = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + PROPERTY_NEW_SET_AUTH + ". Only true, false, or empty is allowed.");
            }
        }

        final String minSdkVersionValue = config.getProperty(MIN_SDK_VERSION);
        if (StringUtils.isNotBlank(minSdkVersionValue)) {
            try {
                minSdkVersion = Optional.of(Integer.parseInt(minSdkVersionValue));
                if (minSdkVersion.get() < 1) {
                    configErrors.add("Illegal value for property " + MIN_SDK_VERSION + ": " + minSdkVersionValue);
                }
            } catch (NumberFormatException e) {
                configErrors.add("Illegal value for property " + MIN_SDK_VERSION + ": " + minSdkVersionValue);
            }
        }
    }

    @Override
    protected boolean isNoCertificates() {
        // the rotate signer doesn't need any crypto of its own, as it references other signers
        return true;
    }

    @Override
    protected boolean isCryptoTokenActive(IServices services) {
        return true;
    }

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

            // Produce the result, ie doing the work...
            Certificate signerCert = null;
            ICryptoInstance cryptoInstanceOld = null;
            ICryptoInstance cryptoInstanceNew = null;
            try (
                    InputStream in = requestData.getAsInputStream();
                    OutputStream out = responseData.getAsOutputStream();
                ) {
                final List<ICryptoInstance> nextSignersCryptos = acquireCryptoInstancesFromOtherSigners(ICryptoTokenV4.PURPOSE_SIGN, signRequest, logMap, requestContext);

                if (nextSignersCryptos.size() != 2) {
                    throw new SignServerException(WorkerConfig.OTHER_SIGNERS + " should contain two signers (old and new).");
                }

                cryptoInstanceOld = nextSignersCryptos.get(0);
                cryptoInstanceNew = nextSignersCryptos.get(1);

                SigningCertificateLineage lineage;
                
                if (in.available() == 0) {
                    // empty request, generate new lineage
                    lineage = createNewSigningCertificateLineage(cryptoInstanceOld,
                                                                 cryptoInstanceNew);
                } else {
                    lineage = ApkLineageUtils.getLineageFromRequest(requestData);
                    lineage = updateSigningCertificateLineage(lineage,
                                                              cryptoInstanceOld,
                                                              cryptoInstanceNew);
                }

                final ByteArrayDataSink sink = new ByteArrayDataSink();
        
                lineage.writeToDataSink(sink);
                final ByteBuffer buffer = sink.getByteBuffer(0L, (int) sink.size());
                
                out.write(buffer.array());
            } finally {
                releaseCryptoInstance(cryptoInstanceOld, requestContext);
                releaseCryptoInstance(cryptoInstanceNew, requestContext);
            }

            // Create the archivables (request and response)
            final String archiveId = createArchiveId(new byte[0],
                    (String) requestContext.get(RequestContext.TRANSACTION_ID));
            final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST,
                                          requestData, archiveId), 
                    new DefaultArchivable(Archivable.TYPE_RESPONSE,
                            RESPONSE_CONTENT_TYPE,
                            responseData.toReadableData(), archiveId));

            // Suggest new file name
            final Object fileNameOriginal = requestContext.get(
                    RequestContext.FILENAME);
            if (fileNameOriginal instanceof String) {
                requestContext.put(RequestContext.RESPONSE_FILENAME,
                        fileNameOriginal + "");
            }

            // As everyting went well, the client can be charged for the request
            requestContext.setRequestFulfilledByWorker(true);

            // Return the response
            return new SignatureResponse(
                    request.getRequestID(), responseData, signerCert, archiveId,
                    archivables, RESPONSE_CONTENT_TYPE);
        } catch (IOException ex) {
            throw new SignServerException("Encoding error", ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new SignServerException("Configured algorithm not supported",
                    ex);
        } catch (InvalidKeyException | CertificateEncodingException | SignatureException ex) {
            throw new SignServerException("Error signing", ex);
        } catch (InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter ex) {
            throw new SignServerException("Error obtaining crypto for new signer", ex);
        }
    }

    private SigningCertificateLineage createNewSigningCertificateLineage(final ICryptoInstance oldCryptoInstance,
                                                                         final ICryptoInstance newCryptoInstance)
            throws CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        final SigningCertificateLineage.SignerConfig oldSignerConfig =
                ApkLineageUtils.getSignerConfigForCryptoInstance(oldCryptoInstance);
        final SigningCertificateLineage.SignerConfig newSignerConfig =
                ApkLineageUtils.getSignerConfigForCryptoInstance(newCryptoInstance);
        SigningCertificateLineage.Builder builder = new SigningCertificateLineage.Builder(oldSignerConfig, newSignerConfig);

        if (minSdkVersion.isPresent()) {
            builder = builder.setMinSdkVersion(minSdkVersion.get());
        }

        final SignerCapabilities.Builder oldCapsBuilder = createOldCapsBuilder();
        final SignerCapabilities.Builder newCapsBuilder = createNewCapsBuilder();

        if (oldCapsBuilder != null) {
            builder.setOriginalCapabilities(oldCapsBuilder.build());
        }
        if (newCapsBuilder != null) {
            builder.setNewCapabilities(newCapsBuilder.build());
        }
        
        return builder.build();
    }

    private SignerCapabilities.Builder createOldCapsBuilder() {
        if (oldSetInstalledData.isPresent() || oldSetSharedUid.isPresent() ||
            oldSetPermission.isPresent() || oldSetRollback.isPresent() ||
            oldSetAuth.isPresent()) {
            SignerCapabilities.Builder capsBuilder = new SignerCapabilities.Builder();

            if (oldSetInstalledData.isPresent()) {
                capsBuilder = capsBuilder.setInstalledData(oldSetInstalledData.get());
            }
            if (oldSetSharedUid.isPresent()) {
                capsBuilder = capsBuilder.setSharedUid(oldSetSharedUid.get());
            }
            if (oldSetPermission.isPresent()) {
                capsBuilder = capsBuilder.setPermission(oldSetPermission.get());
            }
            if (oldSetRollback.isPresent()) {
                capsBuilder = capsBuilder.setRollback(oldSetRollback.get());
            }
            if (oldSetAuth.isPresent()) {
                capsBuilder = capsBuilder.setAuth(oldSetAuth.get());
            }

            return capsBuilder;
        } else {
            return null;
        }
    }

    private SignerCapabilities.Builder createNewCapsBuilder() {
        if (newSetInstalledData.isPresent() || newSetSharedUid.isPresent() ||
            newSetPermission.isPresent() || newSetRollback.isPresent() ||
            newSetAuth.isPresent()) {
            SignerCapabilities.Builder capsBuilder = new SignerCapabilities.Builder();

            if (newSetInstalledData.isPresent()) {
                capsBuilder = capsBuilder.setInstalledData(newSetInstalledData.get());
            }
            if (newSetSharedUid.isPresent()) {
                capsBuilder = capsBuilder.setSharedUid(newSetSharedUid.get());
            }
            if (newSetPermission.isPresent()) {
                capsBuilder = capsBuilder.setPermission(newSetPermission.get());
            }
            if (newSetRollback.isPresent()) {
                capsBuilder = capsBuilder.setRollback(newSetRollback.get());
            }
            if (newSetAuth.isPresent()) {
                capsBuilder = capsBuilder.setAuth(newSetAuth.get());
            }

            return capsBuilder;
        } else {
            return null;
        }
    }

    private SigningCertificateLineage updateSigningCertificateLineage(final SigningCertificateLineage lineage,
                                                    final ICryptoInstance oldCryptoInstance,
                                                    final ICryptoInstance newCryptoInstance)
            throws CertificateEncodingException, InvalidKeyException,
                   NoSuchAlgorithmException, SignatureException {
        final SigningCertificateLineage.SignerConfig oldSignerConfig =
                ApkLineageUtils.getSignerConfigForCryptoInstance(oldCryptoInstance);

        final SigningCertificateLineage.SignerConfig newSignerConfig =
                ApkLineageUtils.getSignerConfigForCryptoInstance(newCryptoInstance);
        final SignerCapabilities.Builder newCapsBuilder = createNewCapsBuilder();

        if (newCapsBuilder != null) {
            return lineage.spawnDescendant(oldSignerConfig, newSignerConfig,
                                           newCapsBuilder.build());
        } else {
            return lineage.spawnDescendant(oldSignerConfig, newSignerConfig);
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

}
