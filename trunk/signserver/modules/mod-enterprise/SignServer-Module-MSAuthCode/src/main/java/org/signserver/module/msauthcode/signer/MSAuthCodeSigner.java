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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
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
import net.jsign.AuthenticodeSigner;
import net.jsign.DigestAlgorithm;
import net.jsign.PESigner;
import net.jsign.asn1.authenticode.AuthenticodeDigestCalculatorProvider;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.AuthenticodeSignedDataGenerator;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.msi.MSIFile;
import org.bouncycastle.cms.*;
import net.jsign.pe.PEFile;
import net.jsign.script.PowerShellScript;
import net.jsign.timestamp.Timestamper;
import net.jsign.timestamp.TimestampingException;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.apache.poi.poifs.filesystem.DirectoryEntry;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.module.msauthcode.common.AuthCodeUtils;
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
import org.signserver.module.msauthcode.common.MSIUtils;
import org.signserver.module.msauthcode.common.SpcSipInfo;

/**
 * Signer for MS portable executable (.exe), Windows Installer (.msi) files and
 * PowerShell scripts (.ps1).
 *
 * Windows Authenticode Portable Executable Signature Format, 1.0, August 29, 2008:
 * http://msdn.microsoft.com/en-us/subscriptions/gg463180 
 *
 * @author Markus Kilås
 * @author Marcus Lundblad
 * @version $Id$
 */
public class MSAuthCodeSigner extends BaseSigner {
    
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

    /**
     * Input file types.
     *
     * Currently supports Portable executable (PE), 
     * Microsoft installer (MSI) formats and Power Shell (PS1).
     */
    private enum FileType {
        PE,
        MSI,
        PS1
    }
    
    /** Request metadata parameter FILE_TYPE. */
    private final String FILE_TYPE = "FILE_TYPE";
    
    /** Log field for the FILE_TYPE. */
    private final String LOG_FILE_TYPE = "FILE_TYPE";

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
    
    /**
     * Copy or move request data file to response data file, depending on the
     * NO_REQUEST_ARCHIVING worker property.
     *
     * If NO_REQUEST_ARCHIVING is true, the file is moved (by accessing request
     * and response data as files), otherwise data is copied from the input
     * to the output stream passed in.
     *
     * @param data Request data to get request file
     * @param responseData Response data to get response file
     * @param in Input stream to use when copying
     * @param out Output stream to use when copying
     * @throws IOException
     */
    private void copyOrMoveInToOut(final ReadableData data,
                                   final WritableData responseData,
                                   final InputStream in,
                                   final OutputStream out) throws IOException {
        if (noRequestArchiving) {
            Files.move(data.getAsFile().toPath(),
                       responseData.getAsFile().toPath(),
                       StandardCopyOption.REPLACE_EXISTING);
        } else {
            IOUtils.copyLarge(in, out);
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
            if (LOG.isDebugEnabled()) {
                LOG.debug("SigningCert: " + ((X509Certificate) signerCert).getSubjectDN());
            }

            // Private key
            PrivateKey privKey = cryptoInstance.getPrivateKey();

            // Write out the origninal file to the response file
            // Note that jsign will modify this file
            final FileType fileType;
            
            try (
                    InputStream in = new BufferedInputStream(data.getAsInputStream());
                    OutputStream out = responseData.getAsFileOutputStream();
                ) {
                
                final String requestedFileType = RequestMetadata.getInstance(requestContext).get(FILE_TYPE);
                
                if (requestedFileType == null) {
                    fileType = getTypeOfFile(requestContext, in);
                } else {
                    try {
                        fileType = FileType.valueOf(requestedFileType);
                    } catch (IllegalArgumentException ex) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Unrecognized file type requested: " + requestedFileType, ex);
                        }
                        throw new IllegalRequestException("Unrecognized file type requested: " + requestedFileType);
                    }
                }
                
                if (fileType == null) {
                    throw new IllegalRequestException("Unable to detect file type");
                }
                
                logMap.put(LOG_FILE_TYPE, fileType.name());

                final String sigAlg;
                if (signatureAlgorithm == null) {
                    sigAlg = "SHA256with" + privKey.getAlgorithm();
                } else {
                    sigAlg = signatureAlgorithm;
                }

                
                switch (fileType) {
                    case PE: {
                        final File outFile = responseData.getAsFile();

                        copyOrMoveInToOut(data, responseData, in, out);
                        return signPE(outFile, certs, privKey, sigAlg,
                                      requestContext, logMap, sReq);
                    }
                    case MSI: {
                        return signMSI(cryptoInstance, certs, sigAlg, requestContext,
                                logMap, sReq);
                    }
                    case PS1: {
                        final File outFile = responseData.getAsFile();

                        copyOrMoveInToOut(data, responseData, in, out);
                        return signPS1(outFile, certs, privKey, sigAlg,
                                      requestContext, logMap, sReq);
                    }
                    default:
                        // this should not happen
                        throw new SignServerException("Unsupported file type: " + fileType.name());
                }
            } catch (IOException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("IO error", ex);
                }
                throw new SignServerException(ex.getMessage());
            }
        } finally {
            if (cryptoInstance != null) {
                releaseCryptoInstance(cryptoInstance, requestContext);
            }
        }
    }
    
    private SignatureResponse signMSI(final ICryptoInstance cryptoInstance, final List<Certificate> certs,
            final String sigAlg,
            final RequestContext requestContext,
            final LogMap logMap,
            final SignatureRequest sReq)
            throws IllegalRequestException, SignServerException, IOException {
        final ReadableData requestData = sReq.getRequestData();
        final WritableData responseData = sReq.getResponseData();
        
        try (
                POIFSFileSystem fs = createFileSystem(requestData, true);
                InputStream in = requestData.getAsInputStream();
                OutputStream out = responseData.getAsFileOutputStream();
        ) {
            final PrivateKey privateKey = cryptoInstance.getPrivateKey();
            final Certificate signerCert = certs.get(0);

            if (LOG.isDebugEnabled()) {
                final StringBuilder sb = new StringBuilder();
                sb.append("Header: ").append(fs.getHeaderBlock()).append("\n");
                sb.append("Property table: ").append(fs.getPropertyTable()).append("\n");
                sb.append("Short description: ").append(fs.getShortDescription()).append("\n");
                sb.append("Viewable array: ").append(Arrays.toString(fs.getViewableArray())).append("\n");
                LOG.debug(sb.toString());
            }

            DirectoryEntry root = fs.getRoot();
            if (LOG.isDebugEnabled()) {
                LOG.debug("root: " + root);
            }

            MessageDigest md = MessageDigest.getInstance(digestAlgorithm.name());
            
            // Calculate digest over all files
            MSIUtils.traverseDirectory(fs, root, md);
            final byte[] messageDigest = md.digest();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Message Digest: " + Hex.toHexString(messageDigest));
            }

            final SpcSipInfo sipInfo = MSIUtils.createMSISpcSipInfo();
            final SpcIndirectDataContent idc = new SpcIndirectDataContent(new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID, sipInfo), new DigestInfo(new AlgorithmIdentifier(digestAlgorithm.oid), messageDigest));
            final AuthenticodeDigestCalculatorProvider calcProvider =
                    new AuthenticodeDigestCalculatorProvider(); // Note: Does not set a provider currently, if this causes an issue we might have to explicitly specify BC

            final AuthenticodeSignedDataGenerator generator
                    = new AuthenticodeSignedDataGenerator();
            // prepare the authenticated attributes
            final CMSAttributeTableGenerator attributeTableGenerator =
                    new DefaultSignedAttributeTableGenerator(
                            MSAuthCodeUtils.createAuthenticatedAttributes(requestContext,
                                                                          authCodeOptions));
            // prepare the signerInfo with the extra authenticated attributes
            final JcaSignerInfoGeneratorBuilder sigBuilder =
                    new JcaSignerInfoGeneratorBuilder(calcProvider);
            sigBuilder.setSignedAttributeGenerator(attributeTableGenerator);
      
            final ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg).setProvider(cryptoInstance.getProvider()).build(privateKey);
            generator.addSignerInfoGenerator(sigBuilder.build(contentSigner, (X509Certificate) signerCert));
            generator.addCertificates(new JcaCertStore(includedCertificates(certs)));

            CMSSignedData signedData2 = generator.generate(AuthenticodeObjectIdentifiers.SPC_INDIRECT_DATA_OBJID, idc);


            if (tsaURL != null || tsaWorker != null) {
                final Timestamper timestamper = createTimestamper(requestContext);
                
                if (tsaURL != null) {
                    timestamper.setURL(tsaURL);
                }
                
                signedData2 = timestamper.timestamp(digestAlgorithm, signedData2);
            }

            MSIFile msiFile = new MSIFile(requestData.getAsFile());
            final List<CMSSignedData> signatures = msiFile.getSignatures();
            if (!signatures.isEmpty()) {
                // append the nested signature
                signedData2 = AuthCodeUtils.addNestedSignature(signatures.get(0),signedData2);
            }

            final byte[] signedbytes = signedData2.toASN1Structure().getEncoded("DER");
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("Version: " + signedData2.getVersion());
                LOG.debug("Size: " + signedbytes.length);
            }

            copyOrMoveInToOut(requestData, responseData, in, out);
          
            try (final POIFSFileSystem fsOut =
                    new POIFSFileSystem(responseData.getAsFile(), false)) {
                // Add the signature file
                fsOut.createOrUpdateDocument(new ByteArrayInputStream(signedbytes), "\05DigitalSignature");

                // Write out
                fsOut.writeFilesystem();

                // Create the archivables (request and response)
                final String archiveId = createArchiveId(new byte[0],
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST, REQUEST_CONTENT_TYPE,
                                          requestData, archiveId),
                    new DefaultArchivable(Archivable.TYPE_RESPONSE, RESPONSE_CONTENT_TYPE,
                                          responseData.toReadableData(), archiveId));

                return new SignatureResponse(sReq.getRequestID(), responseData, signerCert,
                                             archiveId, archivables,
                                             RESPONSE_CONTENT_TYPE);
            }
        } catch (TimestampingException ex) {
            throw new SignServerException("Unable to time-stamp", ex);
        } catch (OperatorCreationException | CertificateEncodingException | CMSException | NoSuchAlgorithmException ex) {
                throw new SignServerException("Error signing", ex);
        }
    }

    private POIFSFileSystem createFileSystem(final ReadableData requestData,
                                             final boolean readOnly) throws IOException {
        final POIFSFileSystem result;
        /* This does not work: an exception is throwed at end of file, maybe because it is openned read-only */
        if (requestData.isFile()) {
            result = new POIFSFileSystem(requestData.getAsFile(), readOnly);
        } else {
            result = new POIFSFileSystem(requestData.getAsInputStream());
            
            
        }
        return result;
    }
    
    private SignatureResponse signPS1(final File outFile,
                                     final List<Certificate> certs,
                                     final PrivateKey privKey,
                                     final String sigAlg,
                                     final RequestContext requestContext,
                                     final LogMap logMap,
                                     final SignatureRequest sReq)
            throws IllegalRequestException, SignServerException, IOException {
        PowerShellScript ps1 = null;
        final String archiveId;
        final Certificate signerCert = certs.get(0);
        final ReadableData requestData = sReq.getRequestData();
        final WritableData responseData = sReq.getResponseData();
        
        try {
            try {
                // Now modify the response file
                ps1 = new PowerShellScript(outFile);

            } catch (IOException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unable to parse input as PowerShell script (PS1): " + ex.getMessage(), ex);
                }
                throw new IllegalRequestException("Unable to parse input as PowerShell script (PS1)", ex);
            }

            final AuthenticodeSigner signer = new AuthenticodeSigner(includedCertificates(certs).toArray(new Certificate[0]), privKey);
            
            if (tsaURL != null || tsaWorker != null) {
                final Timestamper timestamper = createTimestamper(requestContext);

                signer.withTimestamping(true);
                signer.withTimestamper(timestamper);
                signer.withTimestampingRetries(0);
            
                if (tsaURL != null) {
                    signer.withTimestampingAuthority(tsaURL);
                }
            } else {
                signer.withTimestamping(false);
            }
            
            final String programName = authCodeOptions.getProgramName();
            if (programName != null) {
                signer.withProgramName(programName);
            }
            final String programURL = authCodeOptions.getProgramURL();
            if (programURL != null) {
                signer.withProgramURL(programURL);
            }
            
            final String requestedName = RequestMetadata.getInstance(requestContext).get(MSAuthCodeOptions.PROGRAM_NAME);
            final String requestedURL = RequestMetadata.getInstance(requestContext).get(MSAuthCodeOptions.PROGRAM_URL);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Configured programName: " + programName + ", configured programURL: " + programURL
                        + "\nRequested programName: " + requestedName + ", requested programURL: " + requestedURL);
            }
            
            if (requestedName != null) {
                if (authCodeOptions.isAllowProgramNameOverride()) {
                    if (requestedName.trim().isEmpty()) { // Treat empty as removal of name
                        signer.withProgramName(null);
                    } else {
                        signer.withProgramName(requestedName);
                    }
                } else {
                    throw new IllegalRequestException("Requesting PROGRAM_NAME not allowed.");
                }
            }
            
            if (requestedURL != null) {
                if (authCodeOptions.isAllowProgramURLOverride()) {
                    if (requestedURL.trim().isEmpty()) { // Treat empty as removal of name
                        signer.withProgramURL(null);
                    } else {
                        signer.withProgramURL(requestedURL);
                    }
                } else {
                    throw new IllegalRequestException("Requesting PROGRAM_URL not allowed.");
                }
            }

            signer.withDigestAlgorithm(digestAlgorithm);
            signer.withSignatureAlgorithm(sigAlg);

            try {
                signer.sign(ps1);
            } catch (Exception ex) {
                throw new SignServerException(ex.getMessage());
            }

            archiveId = createArchiveId(new byte[0], (String) requestContext.get(RequestContext.TRANSACTION_ID));

            final byte[] responseDigest;
            if (doLogResponseDigest) {
                logMap.put(IWorkerLogger.LOG_RESPONSE_DIGEST_ALGORITHM,
                           new Loggable() {
                               @Override
                               public String toString() {
                                   return logResponseDigestAlgorithm;
                               }
                           });
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
            
            final Collection<? extends Archivable> archivables = Arrays.asList(
                new DefaultArchivable(Archivable.TYPE_REQUEST, REQUEST_CONTENT_TYPE,
                                      requestData, archiveId),
                new DefaultArchivable(Archivable.TYPE_RESPONSE, RESPONSE_CONTENT_TYPE,
                                      responseData.toReadableData(), archiveId));

            // The client can be charged for the request
            requestContext.setRequestFulfilledByWorker(true);

            return new SignatureResponse(sReq.getRequestID(), responseData,
                                         signerCert, archiveId, archivables,
                                         RESPONSE_CONTENT_TYPE);
        } catch (TimestampingException ex) {
            throw new SignServerException("Unable to time-stamp", ex);
        }
    }
    
    private SignatureResponse signPE(final File outFile,
                                     final List<Certificate> certs,
                                     final PrivateKey privKey,
                                     final String sigAlg,
                                     final RequestContext requestContext,
                                     final LogMap logMap,
                                     final SignatureRequest sReq)
            throws IllegalRequestException, SignServerException, IOException {
        ExtendedPEFile pe = null;
        final String archiveId;
        final Certificate signerCert = certs.get(0);
        final ReadableData requestData = sReq.getRequestData();
        final WritableData responseData = sReq.getResponseData();
        
        try {
            try {
                // Now modify the response file
                pe = new ExtendedPEFile(outFile);

                if (LOG.isDebugEnabled()) {
                    ByteArrayOutputStream bout = new ByteArrayOutputStream();
                    pe.printInfo(bout);
                    LOG.debug("Binary information:\n" + new String(bout.toByteArray()));
                }
            } catch (IOException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unable to parse input as portable executable: " + ex.getMessage(), ex);
                }
                throw new IllegalRequestException("Unable to parse input as portable executable", ex);
            }

            final PESigner signer = new PESigner(includedCertificates(certs).toArray(new Certificate[0]), privKey);
            
            if (tsaURL != null || tsaWorker != null) {
                final Timestamper timestamper = createTimestamper(requestContext);

                signer.withTimestamping(true);
                signer.withTimestamper(timestamper);
                signer.withTimestampingRetries(0);
            
                if (tsaURL != null) {
                    signer.withTimestampingAutority(tsaURL);
                }
            } else {
                signer.withTimestamping(false);
            }
            
            final String programName = authCodeOptions.getProgramName();
            if (programName != null) {
                signer.withProgramName(programName);
            }
            final String programURL = authCodeOptions.getProgramURL();
            if (programURL != null) {
                signer.withProgramURL(programURL);
            }
            
            final String requestedName = RequestMetadata.getInstance(requestContext).get(MSAuthCodeOptions.PROGRAM_NAME);
            final String requestedURL = RequestMetadata.getInstance(requestContext).get(MSAuthCodeOptions.PROGRAM_URL);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Configured programName: " + programName + ", configured programURL: " + programURL
                        + "\nRequested programName: " + requestedName + ", requested programURL: " + requestedURL);
            }
            
            if (requestedName != null) {
                if (authCodeOptions.isAllowProgramNameOverride()) {
                    if (requestedName.trim().isEmpty()) { // Treat empty as removal of name
                        signer.withProgramName(null);
                    } else {
                        signer.withProgramName(requestedName);
                    }
                } else {
                    throw new IllegalRequestException("Requesting PROGRAM_NAME not allowed.");
                }
            }
            
            if (requestedURL != null) {
                if (authCodeOptions.isAllowProgramURLOverride()) {
                    if (requestedURL.trim().isEmpty()) { // Treat empty as removal of name
                        signer.withProgramURL(null);
                    } else {
                        signer.withProgramURL(requestedURL);
                    }
                } else {
                    throw new IllegalRequestException("Requesting PROGRAM_URL not allowed.");
                }
            }

            signer.withDigestAlgorithm(digestAlgorithm);
            signer.withSignatureAlgorithm(sigAlg);

            try {
                signer.sign(pe);
            } catch (Exception ex) {
                throw new SignServerException(ex.getMessage());
            }
            
            // For performance reasons, instead of hashing the document again
            // and use that in the archive id, we let the archive id be based 
            // on the already hashed value as stored in ExtendedPEFile.
            // The call to pe.getCachedDigest() must be done after sign().
            archiveId = createArchiveId(pe.getCachedDigest(), (String) requestContext.get(RequestContext.TRANSACTION_ID));

            final byte[] responseDigest;
            if (doLogResponseDigest) {
                logMap.put(IWorkerLogger.LOG_RESPONSE_DIGEST_ALGORITHM,
                           new Loggable() {
                               @Override
                               public String toString() {
                                   return logResponseDigestAlgorithm;
                               }
                           });
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
            
            final Collection<? extends Archivable> archivables = Arrays.asList(
                new DefaultArchivable(Archivable.TYPE_REQUEST, REQUEST_CONTENT_TYPE,
                                      requestData, archiveId),
                new DefaultArchivable(Archivable.TYPE_RESPONSE, RESPONSE_CONTENT_TYPE,
                                      responseData.toReadableData(), archiveId));

            // The client can be charged for the request
            requestContext.setRequestFulfilledByWorker(true);

            return new SignatureResponse(sReq.getRequestID(), responseData,
                                         signerCert, archiveId, archivables,
                                         RESPONSE_CONTENT_TYPE);
        } catch (TimestampingException ex) {
            throw new SignServerException("Unable to time-stamp", ex);
        } finally {
            if (pe != null) {
                try {
                    pe.close();
                } catch (IOException ex) {
                    LOG.error("Unable to close file", ex);
                }
            }
        }
    }
    
    
    /**
     * Determine the file type based on "magic bytes".
     *
     * @return file type (PE or MSI)
     */
    private FileType getTypeOfFile(RequestContext requestContext, final InputStream in)
        throws FileNotFoundException, IOException {
        
        // Detect PowerShell script by file extension
        final Object fileNameOriginal = requestContext.get(RequestContext.FILENAME);
        if (fileNameOriginal instanceof String) {
            final String name = ((String) fileNameOriginal).toUpperCase(Locale.ENGLISH);
            if (name.endsWith(".PS1") || name.endsWith(".PSD1") || name.endsWith(".PSM1")) {
                return FileType.PS1;
            }
        }

        final byte[] magic = new byte[8];
        final FileType type;
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Input stream: " + in.getClass().getName());
        }
        
        in.mark(8);
        
        int bytesRead = in.read(magic, 0, 8);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Bytes read: " + bytesRead);
        }
        
        if (bytesRead >= 2 && magic[0] == 'M' && magic[1] == 'Z') {
            type = FileType.PE;
        } else if (bytesRead >= 8 &&
                   magic[0] == (byte) 0xD0 && magic[1] == (byte) 0xCF &&
                   magic[2] == (byte) 0x11 && magic[3] == (byte) 0xE0 &&
                   magic[4] == (byte) 0xA1 && magic[5] == (byte) 0xB1 &&
                   magic[6] == (byte) 0x1A && magic[7] == (byte) 0xE1) {
            type = FileType.MSI;
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unsupported file type");
                if (bytesRead > 0) {
                    final StringBuilder sb = new StringBuilder();
                    
                    sb.append("Content: ");
                    for (int i = 0; i < bytesRead; i++) {
                        sb.append(String.format("%02X ", magic[i]));
                    }
                    LOG.debug(sb.toString());
                }
            }
            type = null;
        }
        
        in.reset();
        return type;
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

    /**
     * Extended version of PEFile so that we can save the computed hash of the 
     * document and can use that instead of hashing the file again.
     */
    private static class ExtendedPEFile extends PEFile {

        private byte[] cachedDigest;
        
        public ExtendedPEFile(File file) throws IOException {
            super(file);
        }
        
        @Override
        public byte[] computeDigest(final DigestAlgorithm algorithm) throws IOException {
            final byte[] digest = super.computeDigest(algorithm);
            this.cachedDigest = digest;
            return digest;
        }

        /**
         * Get the cached digest from the sign operation.
         * Note: A call to PESigner.sign() must be performed before this method
         * can be used.
         * @return The cached digest
         * @throws IllegalStateException in case sign was not called
         */
        public byte[] getCachedDigest() {
            if (cachedDigest == null) {
                throw new IllegalStateException("Must call sign before getCachedDigest");
            }
            return cachedDigest;
        }
    }
}
