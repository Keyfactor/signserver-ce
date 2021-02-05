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
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import javax.persistence.EntityManager;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
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
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.log.LogMap;
import org.signserver.server.signers.BaseSigner;

/**
 * APK lineage signer.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ApkLineageSigner extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ApkLineageSigner.class);

    // Content types
    private static final String RESPONSE_CONTENT_TYPE = "application/octet-stream";

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Worker properties
    public static final String PROPERTY_SET_INSTALLED_DATA = "SET_INSTALLED_DATA";
    public static final String PROPERTY_SET_SHARED_UID = "SET_SHARED_UID";
    public static final String PROPERTY_SET_PERMISSION = "SET_PERMISSION";
    public static final String PROPERTY_SET_ROLLBACK = "SET_ROLLBACK";
    public static final String PROPERTY_SET_AUTH = "SET_AUTH";

    // Request meta data parameters
    public static final String PROPERTY_PRINT_CERTS = "PRINT_CERTS";

    // Configuration values
    private Optional<Boolean> setInstalledData = Optional.empty();
    private Optional<Boolean> setSharedUid = Optional.empty();
    private Optional<Boolean> setPermission = Optional.empty();
    private Optional<Boolean> setRollback = Optional.empty();
    private Optional<Boolean> setAuth = Optional.empty();

    private static MessageDigest sha256 = null;
    private static MessageDigest sha1 = null;
    private static MessageDigest md5 = null;

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Read properties
        final String otherSignersValue = config.getProperty(WorkerConfig.OTHER_SIGNERS);
        if (StringUtils.isNotBlank(otherSignersValue)) {
            final String[] nextSigners = otherSignersValue.split(",");
            if (nextSigners.length != 1) {
                configErrors.add(WorkerConfig.OTHER_SIGNERS + " should contain one signer.");
            }
        } else {
            configErrors.add("Must specify " + WorkerConfig.OTHER_SIGNERS + ".");
        }
        
        final String setInstalledDataValue =
                config.getProperty(PROPERTY_SET_INSTALLED_DATA);
        if (StringUtils.isNotBlank(setInstalledDataValue)) {
            if ("true".equals(setInstalledDataValue.toLowerCase(Locale.ENGLISH))) {
                setInstalledData = Optional.of(true);
            } else if ("false".equals(setInstalledDataValue.toLowerCase(Locale.ENGLISH))) {
                setInstalledData = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + PROPERTY_SET_INSTALLED_DATA + ". Only true, false, or empty is allowed.");
            }
        }

        final String setSharedUidValue =
                config.getProperty(PROPERTY_SET_SHARED_UID);
        if (StringUtils.isNotBlank(setSharedUidValue)) {
            if ("true".equals(setSharedUidValue.toLowerCase(Locale.ENGLISH))) {
                setSharedUid = Optional.of(true);
            } else if ("false".equals(setSharedUidValue.toLowerCase(Locale.ENGLISH))) {
                setSharedUid = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + PROPERTY_SET_SHARED_UID + ". Only true, false, or empty is allowed.");
            }
        }

        final String setPermissionValue =
                config.getProperty(PROPERTY_SET_PERMISSION);
        if (StringUtils.isNotBlank(setPermissionValue)) {
            if ("true".equals(setPermissionValue.toLowerCase(Locale.ENGLISH))) {
                setPermission = Optional.of(true);
            } else if ("false".equals(setPermissionValue.toLowerCase(Locale.ENGLISH))) {
                setPermission = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + PROPERTY_SET_PERMISSION + ". Only true, false, or empty is allowed.");
            }
        }

        final String setRollbackValue =
                config.getProperty(PROPERTY_SET_ROLLBACK);
        if (StringUtils.isNotBlank(setRollbackValue)) {
            if ("true".equals(setRollbackValue.toLowerCase(Locale.ENGLISH))) {
                setRollback = Optional.of(true);
            } else if ("false".equals(setRollbackValue.toLowerCase(Locale.ENGLISH))) {
                setRollback = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + PROPERTY_SET_ROLLBACK + ". Only true, false, or empty is allowed.");
            }
        }

        final String setAuthValue = config.getProperty(PROPERTY_SET_AUTH);
        if (StringUtils.isNotBlank(setAuthValue)) {
            if ("true".equals(setAuthValue.toLowerCase(Locale.ENGLISH))) {
                setAuth = Optional.of(true);
            } else if ("false".equals(setAuthValue.toLowerCase(Locale.ENGLISH))) {
                setAuth = Optional.of(false);
            } else {
                configErrors.add("Illegal value for property " + PROPERTY_SET_AUTH + ". Only true, false, or empty is allowed.");
            }
        }
    }

    @Override
    protected boolean isNoCertificates() {
        // the lineage signer doesn't need any crypto of its own, as it references other signers
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
            ICryptoInstance cryptoInstance = null;
            try (
                    InputStream in = requestData.getAsInputStream();
                    OutputStream out = responseData.getAsOutputStream();
                ) {
                final SigningCertificateLineage lineage =
                        ApkLineageUtils.getLineageFromRequest(requestData);
                final RequestMetadata metadata =
                        RequestMetadata.getInstance(requestContext);
                final String printCertsValue = metadata.get(PROPERTY_PRINT_CERTS);
                final boolean printCerts;
                
                if (StringUtils.isNotBlank(printCertsValue)) {
                    if ("true".equals(printCertsValue.toLowerCase(Locale.ENGLISH))) {
                        printCerts = true;
                    } else if ("false".equals(printCertsValue.toLowerCase(Locale.ENGLISH))) {
                        printCerts = false;
                    } else {
                        throw new IllegalRequestException("Illegal value for " +
                                                          PROPERTY_PRINT_CERTS +
                                                          " provided in request: " +
                                                          printCertsValue);
                    }
                } else {
                    printCerts = false;
                }

                if (printCerts) {
                    outputCerts(lineage, out);
                } else {
                    final List<ICryptoInstance> otherSignersCryptos =
                        acquireCryptoInstancesFromOtherSigners(ICryptoTokenV4.PURPOSE_SIGN,
                                                               signRequest,
                                                               logMap,
                                                               requestContext);

                    if (otherSignersCryptos.size() != 1) {
                        throw new SignServerException(WorkerConfig.OTHER_SIGNERS + " should contain one signer.");
                    }

                    cryptoInstance = otherSignersCryptos.get(0);
                    final SigningCertificateLineage.SignerConfig signerConfig =
                            ApkLineageUtils.getSignerConfigForCryptoInstance(cryptoInstance);

                    if (lineage.isSignerInLineage(signerConfig)) {
                        final SignerCapabilities caps =
                                lineage.getSignerCapabilities(signerConfig);
                        SignerCapabilities.Builder capsBuilder =
                                new SignerCapabilities.Builder();

                        if (setInstalledData.isPresent()) {
                            capsBuilder = capsBuilder.setInstalledData(setInstalledData.get());
                        }
                        if (setSharedUid.isPresent()) {
                            capsBuilder = capsBuilder.setSharedUid(setSharedUid.get());
                        }
                        if (setPermission.isPresent()) {
                            capsBuilder = capsBuilder.setPermission(setPermission.get());
                        }
                        if (setRollback.isPresent()) {
                            capsBuilder = capsBuilder.setRollback(setRollback.get());
                        }
                        if (setAuth.isPresent()) {
                            capsBuilder = capsBuilder.setAuth(setAuth.get());
                        }

                        final SignerCapabilities newCaps = capsBuilder.build();
                        if (!newCaps.equals(caps)) {
                            lineage.updateSignerCapabilities(signerConfig, newCaps);
                        } else {
                            LOG.info("No change in capabilities for signer");
                        }
                    } else {
                        throw new IllegalRequestException("Signer not present in lineage: " +
                                                          signerConfig.toString());
                    }
                    // Write the result
                    final ByteArrayDataSink sink = new ByteArrayDataSink();
        
                    lineage.writeToDataSink(sink);
                    final ByteBuffer buffer = sink.getByteBuffer(0L, (int) sink.size());
                
                    out.write(buffer.array());
                }
            } catch (NoSuchAlgorithmException | CertificateEncodingException ex) {
                throw new SignServerException("Failed to parse lineage", ex);
            } finally {
                releaseCryptoInstance(cryptoInstance, requestContext);
            }

            // Create the archivables (request and response)
            final String archiveId = createArchiveId(new byte[0],
                    (String) requestContext.get(RequestContext.TRANSACTION_ID));
            final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST,
                            requestData, archiveId), 
                    new DefaultArchivable(Archivable.TYPE_RESPONSE,
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
        } catch (InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter ex) {
            throw new SignServerException("Error obtaining crypto for other signer", ex);
        }
    }

    private void outputCerts(final SigningCertificateLineage lineage,
                             final OutputStream out)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        final List<X509Certificate> signingCerts =
                lineage.getCertificatesInLineage();
        for (int i = 0; i < signingCerts.size(); i++) {
            final X509Certificate signerCert = signingCerts.get(i);
            final SignerCapabilities signerCapabilities =
                    lineage.getSignerCapabilities(signerCert);
            printCertificate(signerCert, "Signer #" + (i + 1) + " in lineage",
                             out);
            printCapabilities(signerCapabilities, out);
        }
    }

    private static void printCertificate(final X509Certificate cert, final String name,
                                         final OutputStream out)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        try (final PrintWriter writer = new PrintWriter(out)) {
            if (sha256 == null || sha1 == null || md5 == null) {
                sha256 = MessageDigest.getInstance("SHA-256");
                sha1 = MessageDigest.getInstance("SHA-1");
                md5 = MessageDigest.getInstance("MD5");
            }

            writer.println(name + " certificate DN: " + cert.getSubjectDN());
            final byte[] encodedCert = cert.getEncoded();
            writer.println(name + " certificate SHA-256 digest: " + Hex.toHexString(
                    sha256.digest(encodedCert)));
            writer.println(name + " certificate SHA-1 digest: " + Hex.toHexString(
                    sha1.digest(encodedCert)));
            writer.println(
                    name + " certificate MD5 digest: " + Hex.toHexString(md5.digest(encodedCert)));

            // TODO: should we have a parameter corresponding to -verbose in apksigner? comes below...
            {
                final PublicKey publicKey = cert.getPublicKey();
                writer.println(name + " key algorithm: " + publicKey.getAlgorithm());
                int keySize = -1;
                if (publicKey instanceof RSAKey) {
                    keySize = ((RSAKey) publicKey).getModulus().bitLength();
                } else if (publicKey instanceof ECKey) {
                    keySize = ((ECKey) publicKey).getParams()
                            .getOrder().bitLength();
                } else if (publicKey instanceof DSAKey) {
                    // DSA parameters may be inherited from the certificate. We
                    // don't handle this case at the moment.
                    final DSAParams dsaParams = ((DSAKey) publicKey).getParams();
                    if (dsaParams != null) {
                        keySize = dsaParams.getP().bitLength();
                    }
                }
                writer.println(
                        name + " key size (bits): " + ((keySize != -1) ? String.valueOf(keySize)
                                : "n/a"));
                final byte[] encodedKey = publicKey.getEncoded();
                writer.println(name + " public key SHA-256 digest: " + Hex.toHexString(
                        sha256.digest(encodedKey)));
                writer.println(name + " public key SHA-1 digest: " + Hex.toHexString(
                        sha1.digest(encodedKey)));
                writer.println(
                        name + " public key MD5 digest: " + Hex.toHexString(md5.digest(encodedKey)));
            }
        }
    }

    /**
     * Prints the capabilities of the provided object to a supplied output stream.
     * Each of the potential capabilities is displayed along with a boolean
     * indicating whether this object has that capability.
     */
    private static void printCapabilities(final SignerCapabilities capabilities,
                                         final OutputStream out) {
        try (final PrintWriter writer = new PrintWriter(out)) {
            writer.println("Has installed data capability: " + capabilities.hasInstalledData());
            writer.println("Has shared UID capability    : " + capabilities.hasSharedUid());
            writer.println("Has permission capability    : " + capabilities.hasPermission());
            writer.println("Has rollback capability      : " + capabilities.hasRollback());
            writer.println("Has auth capability          : " + capabilities.hasAuth());
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
