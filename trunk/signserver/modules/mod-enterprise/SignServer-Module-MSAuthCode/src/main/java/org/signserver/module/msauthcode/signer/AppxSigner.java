/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.msauthcode.signer;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;

import javax.persistence.EntityManager;
import net.jsign.DigestAlgorithm;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import net.jsign.timestamp.Timestamper;
import net.jsign.timestamp.TimestampingException;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.server.IServices;
import org.signserver.server.UsernamePasswordClientCredential;
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
import org.signserver.server.data.impl.UploadUtil;
import org.signserver.common.data.WritableData;
import org.signserver.server.data.impl.ByteArrayReadableData;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.data.impl.TemporarlyWritableData;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;
import org.signserver.server.signers.BaseSigner;
import org.signserver.utils.timestampers.ExternalAuthenticodeTimestamper;
import org.signserver.utils.timestampers.InternalAuthenticodeTimestamper;
import org.signserver.utils.timestampers.MSExternalRFC3161Timestamper;
import org.signserver.utils.timestampers.MSInternalRFC3161Timestamper;
import org.signserver.utils.timestampers.TimestampFormat;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;



import java.util.ArrayList;

import org.bouncycastle.asn1.DERNull;

import java.io.RandomAccessFile;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import org.signserver.module.msauthcode.common.AppxHelper;
import org.signserver.module.msauthcode.common.SpcSipInfo;

/**
 * Signer for APPX files.
 * 
 * @author Selwyn Oh
 * @version $Id$
 */
public class AppxSigner extends BaseSigner {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(MSAuthCodeSigner.class);

    /** Content-type for the requested data. */
    private static final String REQUEST_CONTENT_TYPE = "application/octet-stream";
    
    /** Content-type for the produced data. */
    private static final String RESPONSE_CONTENT_TYPE = "application/octet-stream";

    // Property constants
    public static final String SIGNATUREALGORITHM = "SIGNATUREALGORITHM";
    public static final String DIGESTALGORITHM = "DIGESTALGORITHM";
 
    public static final String TSA_URL = "TSA_URL";
    public static final String TSA_USERNAME = "TSA_USERNAME";
    public static final String TSA_PASSWORD = "TSA_PASSWORD";
    public static final String TSA_WORKER = "TSA_WORKER";
    public static final String TSA_POLICYOID = "TSA_POLICYOID";
    
    public static final String TIMESTAMP_FORMAT = "TIMESTAMP_FORMAT";

    /** Algorithm for the request digest put in the log. */
    public static final String LOGREQUEST_DIGESTALGORITHM_PROPERTY = "LOGREQUEST_DIGESTALGORITHM";

    /** Algorithm for the request digest put in the log. */
    public static final String LOGRESPONSE_DIGESTALGORITHM_PROPERTY = "LOGRESPONSE_DIGESTALGORITHM";

    /** If the request digest should be created and logged. */
    public static final String DO_LOGREQUEST_DIGEST = "DO_LOGREQUEST_DIGEST";

    /** If the response digest should be created and logged. */
    public static final String DO_LOGRESPONSE_DIGEST = "DO_LOGRESPONSE_DIGEST";

    private static final boolean DEFAULT_DO_LOGREQUEST_DIGEST = true;
    private static final String DEFAULT_LOGREQUEST_DIGESTALGORITHM = "SHA256";
    private static final boolean DEFAULT_DO_LOGRESPONSE_DIGEST = true;
    private static final String DEFAULT_LOGRESPONSE_DIGESTALGORITHM = "SHA256";

    private static final String DEFAULT_DIGESTALGORITHM = "SHA256";

    private static final String DEFAULT_TIMESTAMP_FORMAT = "AUTHENTICODE";
    
    private static final boolean DEFAULT_NO_REQUEST_ARCHIVING = false;

    private LinkedList<String> configErrors;
    private String signatureAlgorithm;
    private DigestAlgorithm digestAlgorithm;

    private MSAuthCodeOptions authCodeOptions;
    
    private String tsaURL;
    private String tsaWorker;
    private String tsaUsername;
    private String tsaPassword;
    private ASN1ObjectIdentifier tsaPolicyOID;
    
    private TimestampFormat timestampFormat;

    private String logRequestDigestAlgorithm;
    private String logResponseDigestAlgorithm;
    private boolean doLogRequestDigest;
    private boolean doLogResponseDigest;
    private boolean noRequestArchiving;
    
    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Configuration errors
        configErrors = new LinkedList<>();

        // Get the signature algorithm
        signatureAlgorithm = config.getProperty(SIGNATUREALGORITHM, DEFAULT_NULL);
        String s = config.getProperty(DIGESTALGORITHM, DEFAULT_DIGESTALGORITHM);
        digestAlgorithm = DigestAlgorithm.of(s);
        if (digestAlgorithm == null) {
            configErrors.add("Incorrect value for " + DIGESTALGORITHM);
        }
        
        tsaURL = config.getProperty(TSA_URL, DEFAULT_NULL);
        tsaWorker = config.getProperty(TSA_WORKER, DEFAULT_NULL);
        tsaUsername = config.getProperty(TSA_USERNAME, DEFAULT_NULL);
        tsaPassword = config.getPropertyThatCouldBeEmpty(TSA_PASSWORD); // Might be empty string
        String value = config.getProperty(TSA_POLICYOID, DEFAULT_NULL);
         if (value != null) {
            try {
                tsaPolicyOID = new ASN1ObjectIdentifier(value.trim());
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
        
        authCodeOptions = new MSAuthCodeOptions();
        authCodeOptions.parse(config, configErrors);
        
        final String timestampFormatString =
                config.getProperty(TIMESTAMP_FORMAT, DEFAULT_TIMESTAMP_FORMAT);
        try {
            if (timestampFormatString.trim().isEmpty()) {
                timestampFormat = TimestampFormat.AUTHENTICODE;
            } else {
                timestampFormat =
                    TimestampFormat.valueOf(timestampFormatString.trim().toUpperCase(Locale.ENGLISH));
            }
        } catch (IllegalArgumentException ex) {
            final StringBuilder sb = new StringBuilder();
            
            sb.append(String.format("Illegal value for %s: %s",
                                    TIMESTAMP_FORMAT, timestampFormatString));
            sb.append("\n");
            sb.append("Possible values:\n");
            
            for (final TimestampFormat format : TimestampFormat.values()) {
               sb.append(format);
               sb.append("\n");
            }
            
            configErrors.add(sb.toString());
        }
        
        // Get the log digest algorithms
        logRequestDigestAlgorithm = config.getProperty(LOGREQUEST_DIGESTALGORITHM_PROPERTY, DEFAULT_LOGREQUEST_DIGESTALGORITHM);
        logResponseDigestAlgorithm = config.getProperty(LOGRESPONSE_DIGESTALGORITHM_PROPERTY, DEFAULT_LOGRESPONSE_DIGESTALGORITHM);
        
        // If the request digest should computed and be logged
        s = config.getProperty(DO_LOGREQUEST_DIGEST, Boolean.toString(DEFAULT_DO_LOGREQUEST_DIGEST));
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
        
        s = config.getProperty(WorkerConfig.NO_REQUEST_ARCHIVING, Boolean.toString(DEFAULT_NO_REQUEST_ARCHIVING));
        if ("true".equalsIgnoreCase(s)) {
            noRequestArchiving = true;
        } else if ("false".equalsIgnoreCase(s)) {
            noRequestArchiving = false;
        } else {
            configErrors.add("Incorrect value for " + WorkerConfig.NO_REQUEST_ARCHIVING);
        }
    }

    @Override
    public Response processData(final Request signRequest,
            final RequestContext requestContext) throws IllegalRequestException,
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
        
        final LogMap logMap = LogMap.getInstance(requestContext);

        final byte[] requestDigest;
        if (doLogRequestDigest) {
            logMap.put(IWorkerLogger.LOG_REQUEST_DIGEST_ALGORITHM,
                       new Loggable() {
                           @Override
                           public String toString() {
                               return logRequestDigestAlgorithm;
                           }
                       });
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

        final Certificate signerCert;
        ICryptoInstance cryptoInstance = null;

        try {
            cryptoInstance = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, signRequest, requestContext);

            // Get certificate chain and signer certificate
            List<Certificate> certs = getSigningCertificateChain(cryptoInstance);
            if (certs == null || certs.isEmpty()) {
                throw new IllegalArgumentException("No certificate chain. This signer needs a certificate.");
            }
            signerCert = certs.get(0);
            ArrayList<Certificate> singleCertList = new ArrayList<Certificate>(Arrays.asList(certs.get(0)));

            if (LOG.isDebugEnabled()) {
                LOG.debug("SigningCert: " + ((X509Certificate) signerCert).getSubjectDN());
                if (certs.size() > 1) {
                    LOG.debug("SigningCert2: " + ((X509Certificate) certs.get(1)).getSubjectDN());
                }
            }

            // Private key
            PrivateKey privKey = cryptoInstance.getPrivateKey();

            try (
                    final RandomAccessFile rafInput = new RandomAccessFile(data.getAsFile(), "r");
                    final RandomAccessFile rafOutput = new RandomAccessFile(responseData.getAsFile(), "rw");
                ) {
                
                //Wrapper for tracking new central directory offset after repackaging Appx file
                AppxHelper.CentralDirectoryOffset cdoOffset = new AppxHelper.CentralDirectoryOffset();

                //Reconstructed central directory after repackaging Appx file
                ByteArrayOutputStream baosReconstructedCentralDirRecords = new ByteArrayOutputStream();
                
                //EOCD field data
                AppxHelper.EocdField eocdValues = new AppxHelper.EocdField();
                
                final byte[] byteArrDigest = AppxHelper.produceSignatureInput(rafInput, rafOutput, digestAlgorithm.name() , cdoOffset, baosReconstructedCentralDirRecords, eocdValues);
                
                long longNewCentralDirOffset = cdoOffset.getCentralDirOffset();

                final PrivateKey privateKey = cryptoInstance.getPrivateKey();
                
                try {
                    final String sigAlg;
                    if (signatureAlgorithm == null) {
                        sigAlg = "SHA256with" + privKey.getAlgorithm();
                    } else {
                        sigAlg = signatureAlgorithm;
                    }
                    
                    final SpcSipInfo sipInfo = MSAuthCodeUtils.createAppxSpcSipInfo();
                    final AppxSpcIndirectDataContent idc2 = new AppxSpcIndirectDataContent(new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID, sipInfo), new DigestInfo(new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE), byteArrDigest));

                    final LegacyAuthenticodeDigestCalculatorProvider calcProvider =
                            new LegacyAuthenticodeDigestCalculatorProvider(); // Note: Does not set a provider currently, if this causes an issue we might have to explicitly specify BC

                    final AppxSignedDataGenerator generator
                            = new AppxSignedDataGenerator();

                    // Prepare the authenticated attributes
                    final CMSAttributeTableGenerator attributeTableGenerator =
                            new AppxSignedAttributeTableGenerator(
                                    MSAuthCodeUtils.createAuthenticatedAttributes(requestContext,
                                                                                  authCodeOptions));

                    // Prepare the signerInfo with the extra authenticated attributes
                    final JcaSignerInfoGeneratorBuilder sigBuilder =
                            new JcaSignerInfoGeneratorBuilder(calcProvider);
                    sigBuilder.setSignedAttributeGenerator(attributeTableGenerator);
                    
                    final ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg).setProvider(cryptoInstance.getProvider()).build(privateKey);
                    generator.addSignerInfoGenerator(sigBuilder.build(contentSigner, (X509Certificate) signerCert));
                    generator.addCertificates(new JcaCertStore(includedCertificates(certs)));
                    CMSSignedData signedData = generator.generate(AuthenticodeObjectIdentifiers.SPC_INDIRECT_DATA_OBJID, idc2);

                    if (tsaURL != null || tsaWorker != null) {
                        final Timestamper timestamper = createTimestamper(requestContext);
                        
                        if (tsaURL != null) {
                            timestamper.setURL(tsaURL);
                        }
                        
                        signedData = timestamper.timestamp(digestAlgorithm, signedData);
                    }

                    byte[] byteArrReconstructedCentralDirRecords = baosReconstructedCentralDirRecords.toByteArray();

                    final byte[] signedBytes = signedData.toASN1Structure().getEncoded("DER");
                    AppxHelper.assemble(rafOutput, signedBytes, longNewCentralDirOffset, byteArrReconstructedCentralDirRecords, eocdValues);
                    
                    final String archiveId = createArchiveId(/*signer.getCachedDigest()*/ /*data*/ new byte[0], (String) requestContext.get(RequestContext.TRANSACTION_ID));
                    final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST, REQUEST_CONTENT_TYPE, data, archiveId),
                    new DefaultArchivable(Archivable.TYPE_RESPONSE, RESPONSE_CONTENT_TYPE, responseData.toReadableData(), archiveId));

                    // The client can be charged for the request
                    requestContext.setRequestFulfilledByWorker(true);

                    // Return the response
                    return new SignatureResponse(sReq.getRequestID(), responseData, signerCert, archiveId, archivables, RESPONSE_CONTENT_TYPE);

                } catch (TimestampingException ex) {
                    throw new SignServerException("Unable to time-stamp", ex);
                } catch (OperatorCreationException | CertificateEncodingException | CMSException ex) {
                    throw new SignServerException("Error signing", ex);
                }

            } catch (IOException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("IO error", ex);
                }
                throw new SignServerException(ex.getMessage());
            } catch (NoSuchAlgorithmException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No such algorithm", ex);
                }
                throw new IllegalRequestException(ex);
            }
        } finally {
            if (cryptoInstance != null) {
                releaseCryptoInstance(cryptoInstance, requestContext);
            }
        }
    }

    private Timestamper createTimestamper(final RequestContext requestContext)
            throws SignServerException {
        final Timestamper timestamper;

        switch (timestampFormat) {
            case AUTHENTICODE:
                if (tsaURL!= null) {
                    timestamper =
                        new ExternalAuthenticodeTimestamper(tsaUsername,
                                                            tsaPassword);
                } else {
                    timestamper =
                        new InternalAuthenticodeTimestamper(tsaWorker,
                                                            tsaUsername,
                                                            tsaPassword,
                                                            getWorkerSession(requestContext));
                }
                break;
            case RFC3161:
                if (tsaURL != null) {
                    timestamper =
                        new MSExternalRFC3161Timestamper(tsaPolicyOID,
                                                       tsaUsername,
                                                       tsaPassword);
                } else {
                    timestamper =
                        new MSInternalRFC3161Timestamper(tsaWorker,
                                                       tsaPolicyOID,
                                                       tsaUsername,
                                                       tsaPassword,
                                                       getWorkerSession(requestContext));
                }
                break;
            default:
                // this shouldn't happen
                throw new SignServerException("Unknown timestamping format: " + timestampFormat.name());
        }

        return timestamper;
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        final LinkedList<String> errors = new LinkedList<>(super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }

    protected InternalProcessSessionLocal getWorkerSession(final RequestContext requestContext) {
        return requestContext.getServices().get(InternalProcessSessionLocal.class);
    }
    
    private static byte[] fetchTimestampInternal(byte[] request,
                                                          String workerNameOrId,
                                                          String username,
                                                          String password,
                                                          int hashCode,
                                                          InternalProcessSessionLocal workerSession,
                                                          File fileRepository)
        throws IOException {
        try (
            CloseableReadableData requestData = new ByteArrayReadableData(request, fileRepository);
            CloseableWritableData responseData = new TemporarlyWritableData(false, fileRepository);
        ) {
            final RequestContext context = new RequestContext();

            if (username != null && password != null) {
                final UsernamePasswordClientCredential cred
                        = new UsernamePasswordClientCredential(username, password);
                context.put(RequestContext.CLIENT_CREDENTIAL, cred);
                context.put(RequestContext.CLIENT_CREDENTIAL_PASSWORD, cred);
            }

            workerSession.process(new AdminInfo("Client user", null, null), WorkerIdentifier.createFromIdOrName(workerNameOrId), new SignatureRequest(hashCode, requestData, responseData), context);

            return responseData.toReadableData().getAsByteArray();
        } catch (IllegalRequestException | CryptoTokenOfflineException |
                 SignServerException ex) {
            throw new IOException(ex);
        }
    }
}
