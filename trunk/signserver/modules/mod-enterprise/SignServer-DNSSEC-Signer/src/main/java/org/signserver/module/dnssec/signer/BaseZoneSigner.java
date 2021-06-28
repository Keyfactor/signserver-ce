/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.dnssec.signer;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.NoSuchAliasException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerConstants;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;
import org.signserver.common.SignServerException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import static org.signserver.module.dnssec.signer.BaseZoneFileServerSideSigner.getZskSequenceNumber;
import static org.signserver.module.dnssec.signer.ZoneHashSigner.PROPERTY_ZSK_KEY_ALIAS_PREFIX;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.CryptoInstances;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import static org.signserver.server.cryptotokens.ICryptoTokenV4.PARAM_INCLUDE_DUMMYCERTIFICATE;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.server.signers.BaseSigner;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.Name;
import org.xbill.DNS.TextParseException;

/**
 * Common functionality for all DNSSEC signers.
 * Provides worker properties and access to DNSSEC keys and their status etc.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class BaseZoneSigner extends BaseSigner {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(BaseZoneSigner.class);
    
    protected static final String RESPONSE_CONTENT_TYPE = "text/plain";
    
    // Worker property constants
    public static final String PROPERTY_SIGNATUREALGORITHM = "SIGNATUREALGORITHM";
    protected static final String PROPERTY_NSEC3_SALT = "NSEC3_SALT";
    protected static final String PROPERTY_ACTIVE_KSKS = "ACTIVE_KSKS";
    protected static final String PROPERTY_ZONE_NAME = "ZONE_NAME";
    protected static final String PROPERTY_ZSK_KEY_ALIAS_PREFIX = "ZSK_KEY_ALIAS_PREFIX";
    protected static final String PROPERTY_FIXEDTIME = "FIXEDTIME";
    protected static final String PROPERTY_PUBLISH_PREVIOUS_ZSK = "PUBLISH_PREVIOUS_ZSK";
    
    // Request metadata property constants
    protected static final String METADATA_ZSK_SEQUENCE_NUMBER = "ZSK_SEQUENCE_NUMBER";
        
    /** Random generator algorithm. */
    protected static final String RANDOM_ALGORITHM = "SHA1PRNG";
    
    /**
     * Random generator.
     */
    protected transient SecureRandom random;
    
    protected final LinkedList<String> configErrors = new LinkedList<>();
    
    // Worker properties
    protected String zskKeyAliasPrefix;
    protected boolean publishPreviousZsk;
    protected final List<String> activeKskAliases = new LinkedList<>();
    protected byte[] decodedSalt;
    protected String zoneName;
    protected Long fixedTime;
    protected int signatureAlgorithmDnssec;
    
    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Default to disable key usage counter for this worker
        if (config.getProperty(SignServerConstants.DISABLEKEYUSAGECOUNTER) == null) {
            config.setProperty(SignServerConstants.DISABLEKEYUSAGECOUNTER, Boolean.TRUE.toString());
        }

        super.init(workerId, config, workerContext, workerEM);

        // Required property ZSK_KEY_ALIAS_PREFIX
        zskKeyAliasPrefix = config.getProperty(PROPERTY_ZSK_KEY_ALIAS_PREFIX);
        if (zskKeyAliasPrefix == null) {
            configErrors.add("Missing " + PROPERTY_ZSK_KEY_ALIAS_PREFIX + " property");
        }
        
        // Optional property PUBLISH_PREVIOUS_ZSK
        final String value = config.getProperty(PROPERTY_PUBLISH_PREVIOUS_ZSK, Boolean.TRUE.toString());
        if (Boolean.TRUE.toString().equalsIgnoreCase(value)) {
            publishPreviousZsk = true;
        } else if (Boolean.FALSE.toString().equalsIgnoreCase(value)) {
            publishPreviousZsk = false;
        } else {
            configErrors.add("Incorrect value for property "
                    + PROPERTY_PUBLISH_PREVIOUS_ZSK);
        }

        // Optional property PUBLISH_PREVIOUS_ZSK
        final String publishPreviousValue = config.getProperty(PROPERTY_NSEC3_SALT, DEFAULT_NULL);
        if (publishPreviousValue != null) {
            try {
                decodedSalt = Hex.decode(publishPreviousValue);
            } catch (DecoderException e) {
                configErrors.add("Malformed " + PROPERTY_NSEC3_SALT + ": " + e.getMessage());
            }
        }
    
        // Optional property NSEC3_SALT
        final String nSec3Salt = config.getProperty(PROPERTY_NSEC3_SALT, DEFAULT_NULL);
        if (nSec3Salt != null) {
            try {
                decodedSalt = Hex.decode(nSec3Salt);
            } catch (DecoderException e) {
                configErrors.add("Malformed " + PROPERTY_NSEC3_SALT + ": " + e.getMessage());
            }
        }
        
        // Required property ACTIVE_KSKS
        final String activeKsksValue = config.getProperty(PROPERTY_ACTIVE_KSKS, DEFAULT_NULL);

        if (activeKsksValue == null) {
            configErrors.add("Missing " + PROPERTY_ACTIVE_KSKS);
        } else {
            final String[] aliases = activeKsksValue.split(",");

            for (final String alias : aliases) {
                final String trimmedAlias = alias.trim();

                activeKskAliases.add(trimmedAlias);
            }

            final int numberOfKskAliases = activeKskAliases.size();

            if (numberOfKskAliases < 1 || numberOfKskAliases > 2) {
                configErrors.add("Must specify exactly 1 or 2 active KSKs");
            }
        }

        // Required property ZONE_NAME
        zoneName = config.getProperty(PROPERTY_ZONE_NAME, DEFAULT_NULL);

        // TODO: maybe parse zone name from zone file, if not set
        if (zoneName == null) {
            configErrors.add("Missing ZONE_NAME");
        }
        
        // Optional property FIXEDTIME
        final String fixedTimeValue = config.getProperty(PROPERTY_FIXEDTIME, DEFAULT_NULL);
        if (fixedTimeValue != null) {
            try {
                fixedTime = Long.parseLong(fixedTimeValue);
            } catch (NumberFormatException ex) {
                configErrors.add("Expected nummeric value for " + PROPERTY_FIXEDTIME + ": " + ex.getMessage());
            }
        }

        // Optional property SIGNATUREALGORITHM
        try {
            signatureAlgorithmDnssec = getDnssecAlgorithm(config.getProperty(PROPERTY_SIGNATUREALGORITHM, DEFAULT_NULL));
        } catch (IllegalArgumentException e) {
            configErrors.add("Unsupported signature algorithm: " +
                             config.getProperty(PROPERTY_SIGNATUREALGORITHM));
        }

        // property DISABLEKEYUSAGECOUNTER
        final boolean keyUsageCounterDisabled = config.getProperty(SignServerConstants.DISABLEKEYUSAGECOUNTER, "FALSE").equalsIgnoreCase("TRUE");
        if (!keyUsageCounterDisabled) {
            configErrors.add(SignServerConstants.DISABLEKEYUSAGECOUNTER + " must be TRUE for this signer");
        }
    }
    
    @Override
    public Response processData(final Request signRequest,
            final RequestContext requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {        
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
                                     
            // Log anything interesting from the request to the worker logger
            //...
            // Produce the result, ie doing the work...
            Certificate signerCert = null;
            List<ICryptoInstance> zskCryptoInstances = new ArrayList<>(2);
            List<ICryptoInstance> kskCryptoInstances = new LinkedList<>();
            try (OutputStream out = responseData.getAsFileOutputStream()) {
                // Get sequence number from request
                final int zskSequenceNumber = getZskSequenceNumber(requestContext);
                                
                // Get first ZSK (the one to sign with)
                final String zskAlias1 = zskKeyAliasPrefix + zskSequenceNumber;
                zskCryptoInstances.add(acquireKskCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN,
                        zskAlias1,
                        requestContext));

                // Get second ZSK (the one which public key should be published)
                final String zskAlias2 = zskKeyAliasPrefix + (zskSequenceNumber + 1);
                zskCryptoInstances.add(acquireKskCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN,
                        zskAlias2,
                        requestContext));
                
                // Get the previous ZSK (the one which if exists, should still be published)
                if (publishPreviousZsk) {
                    try {
                        final String zskAlias0 = zskKeyAliasPrefix + (zskSequenceNumber - 1);
                        zskCryptoInstances.add(acquireKskCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN,
                            zskAlias0,
                            requestContext));
                    }  catch (CryptoTokenOfflineException ex) {
                        LOG.info("Unable to obtain previous ZSK so no post-publishing of previous key: " + ex.getMessage());
                    }
                }

                // Log main key alias used
                LogMap.getInstance(requestContext).put(IWorkerLogger.LOG_KEYALIAS, zskAlias1);

                // Get the KSK:s
                for (final String alias : activeKskAliases) {
                    final ICryptoInstance kskCryptoInstance
                            = acquireKskCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN,
                                    alias,
                                    requestContext);

                    kskCryptoInstances.add(kskCryptoInstance);
                }

                try {
                    signData(requestData, requestContext, out, zskCryptoInstances,
                             kskCryptoInstances);
                } catch (TextParseException | NoSuchAlgorithmException
                        | FileNotFoundException | DNSSEC.DNSSECException | InvalidKeyException | SignatureException ex) {
                    LOG.error("Error while signing", ex);
                    throw new SignServerException("Error while signing", ex);
                }
            } finally {
                for (final ICryptoInstance instance : zskCryptoInstances) {
                    releaseCryptoInstance(instance, requestContext);
                }
                for (final ICryptoInstance instance : kskCryptoInstances) {
                    releaseCryptoInstance(instance, requestContext);
                }
            }

            // Create the archivables (request and response)
            final String archiveId = createArchiveId(new byte[0],
                    (String) requestContext.get(RequestContext.TRANSACTION_ID));
            final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST,
                            getRequestContentType(), requestData, archiveId),
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
        }
    }

    /**
     * Signature implementation to be provided by the concrete signer implementations.
     *
     * @param requestData the request
     * @param requestContext the context
     * @param out stream to write to
     * @param zskCryptoInstances all the ZSK instances that should be used
     * @param kskCryptoInstances all the KSK instances that should be used
     * @throws TextParseException
     * @throws NoSuchAlgorithmException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws org.xbill.DNS.DNSSEC.DNSSECException
     * @throws IllegalArgumentException
     * @throws IllegalRequestException
     * @throws InvalidKeyException
     * @throws SignatureException 
     */
    protected abstract void signData(ReadableData requestData, RequestContext requestContext, OutputStream out, List<ICryptoInstance> zskCryptoInstances, List<ICryptoInstance> kskCryptoInstances) throws TextParseException, NoSuchAlgorithmException,
                   FileNotFoundException, IOException, DNSSEC.DNSSECException, IllegalArgumentException, IllegalRequestException, InvalidKeyException, SignatureException;
    
    @Override
    protected List<String> getFatalErrors(final IServices services) {
        final LinkedList<String> errors = new LinkedList<>(super.getFatalErrors(services));
        errors.addAll(configErrors);

        List<ICryptoInstance> kskCryptoInstances = new LinkedList<>();
        final Map<String, Object> newParams = new HashMap<>();
        final RequestContext context = new RequestContext(true);
        context.setServices(services);
        newParams.put(PARAM_INCLUDE_DUMMYCERTIFICATE, true);
        try {
            for (final String alias : activeKskAliases) {
                final ICryptoInstance kskCryptoInstance
                        = acquireDefaultCryptoInstance(newParams,
                                alias, context);

                kskCryptoInstances.add(kskCryptoInstance);
            }
        } catch (CryptoTokenOfflineException | InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter | IllegalRequestException | SignServerException ex) {
            errors.add("Error while aquiring "+ PROPERTY_ACTIVE_KSKS);
            LOG.error("Error while aquiring "+ PROPERTY_ACTIVE_KSKS, ex);
        } finally {
            kskCryptoInstances.forEach((kskCryptoInstance) -> {
                try {
                    releaseCryptoInstance(kskCryptoInstance, context);
                } catch (SignServerException ex) {
                    LOG.warn("Unable to release crypto instance", ex);
                }
            });
        }

        return errors;
    }
    /**
     * This Signer does not require to be configured with any certificates
     * during initialization and crypto token referenced by worker requires no
     * certificates.
     * @return true as this signer does not use certificates
     */
    @Override
    protected boolean isNoCertificates() {
        return true;
    }
    
    /**
     * Determines request content type based on implementation signer functionality.
     *
     * @return request content type (i.e. text/plain or application/zip)
     */
    protected abstract String getRequestContentType();
    
    private ICryptoInstance acquireKskCryptoInstance(final int purpose,
                                                       final String keyAlias,
                                                       final RequestContext context)
            throws SignServerException, CryptoTokenOfflineException,
                   IllegalRequestException {
        final ICryptoInstance result;
        ICryptoTokenV4 token = getCryptoToken(context.getServices());
        if (token == null) {
            throw new CryptoTokenOfflineException("Crypto token not available");
        }
        try {
            result = token.acquireCryptoInstance(keyAlias, Collections.emptyMap(), context);
        } catch (NoSuchAliasException ex) {
            throw new CryptoTokenOfflineException("Key not available: " + ex.getMessage());
        } catch (UnsupportedCryptoTokenParameter ex) {
            throw new SignServerException("Empty list of parameters not supported by crypto token", ex);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new SignServerException("Empty list of parameters reported as invalid by crypto token", ex);
        }

        // Register the new instance
        CryptoInstances.getInstance(context).add(result);

        return result;
    }

    protected String getDefaultSignatureAlgorithm(final PublicKey publicKey) {
        final String result;

        if (publicKey instanceof ECPublicKey) {
            result = "NONEwithECDSA";
        }  else if (publicKey instanceof DSAPublicKey) {
            result = "NONEwithDSA";
        } else {
            result = "NONEwithRSA";
        }

        return result;
    }
    
    protected static int getDnssecAlgorithm(String signatureAlgorithmString) {

        if (signatureAlgorithmString == null) {
            return DNSSEC.Algorithm.RSASHA256;
        } else {
            switch (signatureAlgorithmString.toLowerCase(Locale.ENGLISH)) {
                case "sha1withrsa":
                    return DNSSEC.Algorithm.RSA_NSEC3_SHA1;
                case "sha256withrsa":
                    return DNSSEC.Algorithm.RSASHA256;
                case "sha512withrsa":
                    return DNSSEC.Algorithm.RSASHA512;
                default:
                    throw new IllegalArgumentException("Unsupported signature algorithm");
            }
        }
    }
    
    @Override
    public WorkerStatusInfo getStatus(final List<String> additionalFatalErrors, final IServices services) {
        WorkerStatusInfo status = (WorkerStatusInfo) super.getStatus(additionalFatalErrors, services);

        String algorithm;
        algorithm = DNSSEC.Algorithm.string(signatureAlgorithmDnssec);
        
        status.getCompleteEntries().add(new WorkerStatusInfo.Entry("DNSKEY Algorithm", algorithm));
        
        final RequestContext context = new RequestContext(true);
        context.setServices(services);

        try {
            // Get the KSK:s
            for (final String alias : activeKskAliases) {
                String title = "KSK " + alias;
                String keyRecord;
                ICryptoInstance kskCrypto = null;
                try {
                    kskCrypto = acquireKskCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, alias, context);
                    final DNSKEYRecord dnskeyKSK = new DNSKEYRecord(Name.fromString(zoneName), DClass.IN, 84600, 0x101, DNSKEYRecord.Protocol.DNSSEC, signatureAlgorithmDnssec, kskCrypto.getPublicKey());
                    keyRecord = "DNSKEY " + dnskeyKSK.rdataToString();
                    title += " (" + dnskeyKSK.getFootprint() +")";
                } catch (SignServerException | CryptoTokenOfflineException ex) {
                    keyRecord = "Error: " + ex.getLocalizedMessage();
                } finally {
                    releaseCryptoInstance(kskCrypto, context);
                }
                status.getCompleteEntries().add(new WorkerStatusInfo.Entry(title, keyRecord));
            }
        } catch (IllegalRequestException | SignServerException | DNSSEC.DNSSECException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unable to obtain public key from token", ex);
            }
        } catch (IOException ex) {
            LOG.error("Unable to encode DNSSEC key", ex);
        }

        return status;
    }
}
