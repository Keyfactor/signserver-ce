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
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import javax.persistence.EntityManager;
import net.jsign.DigestAlgorithm;
import net.jsign.PESigner;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.AuthenticodeSignedDataGenerator;
import net.jsign.asn1.authenticode.AuthenticodeTimeStampRequest;
import net.jsign.asn1.authenticode.SpcSpOpusInfo;
import net.jsign.asn1.authenticode.SpcStatementType;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import net.jsign.pe.PEFile;
import net.jsign.timestamp.AuthenticodeTimestamper;
import net.jsign.timestamp.RFC3161Timestamper;
import net.jsign.timestamp.Timestamper;
import net.jsign.timestamp.TimestampingException;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.apache.poi.poifs.filesystem.DirectoryEntry;
import org.apache.poi.poifs.filesystem.NPOIFSFileSystem;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
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
import org.signserver.server.data.impl.UploadConfig;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;
import org.signserver.server.signers.BaseSigner;

/**
 * Signer for MS portable executable files.
 * 
 * Windows Authenticode Portable Executable Signature Format, 1.0, August 29, 2008:
 * http://msdn.microsoft.com/en-us/subscriptions/gg463180 
 *
 * @author Markus Kilås
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

    public static final String PROGRAM_NAME = "PROGRAM_NAME";
    public static final String PROGRAM_URL = "PROGRAM_URL";
    public static final String ALLOW_PROGRAM_NAME_OVERRIDE = "ALLOW_PROGRAM_NAME_OVERRIDE";
    public static final String ALLOW_PROGRAM_URL_OVERRIDE = "ALLOW_PROGRAM_URL_OVERRIDE";
 
    public static final String TSA_URL = "TSA_URL";
    public static final String TSA_USERNAME = "TSA_USERNAME";
    public static final String TSA_PASSWORD = "TSA_PASSWORD";
    public static final String TSA_WORKER = "TSA_WORKER";
    
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

    private static final String DEFAULT_DIGESTALGORITHM = "SHA-1";
    private static final boolean DEFAULT_ALLOW_PROGRAM_NAME_OVERRIDE = false;
    private static final boolean DEFAULT_ALLOW_PROGRAM_URL_OVERRIDE = false;
    
    private static final String DEFAULT_TIMESTAMP_FORMAT = "AUTHENTICODE";
    
    private static final boolean DEFAULT_NO_REQUEST_ARCHIVING = false;

    private LinkedList<String> configErrors;
    private String signatureAlgorithm;
    private DigestAlgorithm digestAlgorithm;

    private String programName;
    private String programURL;
    private boolean allowProgramNameOverride;
    private boolean allowProgramURLOverride;

    private String tsaURL;
    private String tsaWorker;
    private String tsaUsername;
    private String tsaPassword;
    
    private TimestampFormat timestampFormat;

    private String logRequestDigestAlgorithm;
    private String logResponseDigestAlgorithm;
    private boolean doLogRequestDigest;
    private boolean doLogResponseDigest;
    private boolean noRequestArchiving;
    
    /**
     * Timestamp formats.
     * 
     * Currently Authenticode and RFC#3161
     */
    private enum TimestampFormat {
        AUTHENTICODE,
        RFC3161
    }

    /**
     * Input file types.
     * 
     * Currently supports Portable executable (PE) and
     * Microsoft installer (MSI) formats.
     */
    private enum FileType {
        PE,
        MSI
    }
    
    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Configuration errors
        configErrors = new LinkedList<>();

        // Get the signature algorithm
        signatureAlgorithm = config.getProperty(SIGNATUREALGORITHM);
        String s = config.getProperty(DIGESTALGORITHM, DEFAULT_DIGESTALGORITHM);
        if (s == null || s.trim().isEmpty()) {
            s = DEFAULT_DIGESTALGORITHM;
        }
        digestAlgorithm = DigestAlgorithm.of(s);
        if (digestAlgorithm == null) {
            configErrors.add("Incorrect value for " + DIGESTALGORITHM);
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
        
        // check that TSA_URL and TSA_WORKER is not set at the same time
        if (tsaURL != null && tsaWorker != null) {
            configErrors.add("Can not specify both " + TSA_URL + " and " + TSA_WORKER + " at the same time.");
        }
        
        // Check that password is specified if username is
        if (tsaUsername != null && tsaPassword == null) {
            configErrors.add("Need to specify " + TSA_PASSWORD + " if " + TSA_USERNAME + " is specified.");
        }
        
        final String timestampFormatString =
                config.getProperty(TIMESTAMP_FORMAT, DEFAULT_TIMESTAMP_FORMAT);
        try {
            if (timestampFormatString.isEmpty()) {
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

        programName = config.getProperty(PROGRAM_NAME);
        if (programName != null && programName.trim().isEmpty()) {
            programName = null;
        }
        programURL = config.getProperty(PROGRAM_URL);
        if (programURL != null && programURL.trim().isEmpty()) {
            programURL = null;
        }
        
        s = config.getProperty(ALLOW_PROGRAM_NAME_OVERRIDE, "false").trim();
        if (s == null || s.trim().isEmpty()) {
            allowProgramNameOverride = DEFAULT_ALLOW_PROGRAM_NAME_OVERRIDE;
        } else if ("true".equalsIgnoreCase(s)) {
            allowProgramNameOverride = true;
        } else if ("false".equalsIgnoreCase(s)) {
            allowProgramNameOverride = false;
        } else {
            configErrors.add("Incorrect value for " + ALLOW_PROGRAM_NAME_OVERRIDE);
        }
        
        s = config.getProperty(ALLOW_PROGRAM_URL_OVERRIDE, "false").trim();
        if (s == null || s.trim().isEmpty()) {
            allowProgramNameOverride = DEFAULT_ALLOW_PROGRAM_URL_OVERRIDE;
        } else if ("true".equalsIgnoreCase(s)) {
            allowProgramURLOverride = true;
        } else if ("false".equalsIgnoreCase(s)) {
            allowProgramURLOverride = false;
        } else {
            configErrors.add("Incorrect value for " + ALLOW_PROGRAM_URL_OVERRIDE);
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

        // If the request digest should computed and be logged
        s = config.getProperty(DO_LOGREQUEST_DIGEST);
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
        
        s = config.getProperty(WorkerConfig.NO_REQUEST_ARCHIVING);
        if (s == null || s.trim().isEmpty()) {
            noRequestArchiving = DEFAULT_NO_REQUEST_ARCHIVING;
        } else if ("true".equalsIgnoreCase(s)) {
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
                
                fileType = getTypeOfFile(in);
                
                if (fileType == null) {
                    throw new IllegalRequestException("Unkown file format");
                }

                final String sigAlg;
                if (signatureAlgorithm == null) {
                    sigAlg = "SHA1with" + privKey.getAlgorithm();
                } else {
                    sigAlg = signatureAlgorithm;
                }

                if (noRequestArchiving) {
                    Files.move(data.getAsFile().toPath(),
                               responseData.getAsFile().toPath(),
                               StandardCopyOption.REPLACE_EXISTING);
                } else {
                    IOUtils.copyLarge(in, out);
                }

                switch (fileType) {
                    case PE:                        
                        final File outFile = responseData.getAsFile();

                        return signPE(outFile, certs, privKey, sigAlg,
                                      requestContext, logMap, sReq);
                      
                    case MSI:
                        return signMSI(cryptoInstance, sigAlg, requestContext,
                                       logMap, sReq);
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
    
    private SignatureResponse signMSI(final ICryptoInstance cryptoInstance,
                                      final String sigAlg,
                                      final RequestContext requestContext,
                                      final LogMap logMap,
                                      final SignatureRequest sReq)
            throws IllegalRequestException, SignServerException, IOException {
        final ReadableData requestData = sReq.getRequestData();
        final WritableData responseData = sReq.getResponseData();
        
        try (
                NPOIFSFileSystem fs = createFileSystem(requestData, true);
                OutputStream out = responseData.getAsFileOutputStream();
        ) {
            final PrivateKey privateKey = cryptoInstance.getPrivateKey();
            final X509Certificate cert = (X509Certificate) cryptoInstance.getCertificate();
            final List<Certificate> certs = cryptoInstance.getCertificateChain();

            if (LOG.isDebugEnabled()) {
                final StringBuilder sb = new StringBuilder();
                sb.append("Header: ").append(fs.getHeaderBlock()).append("\n");
                sb.append("Property table: ").append(fs.getPropertyTable()).append("\n");
                sb.append("Ministore: ").append(fs.getMiniStore()).append("\n");
                sb.append("Short description: ").append(fs.getShortDescription()).append("\n");
                sb.append("Viewable array: ").append(Arrays.toString(fs.getViewableArray())).append("\n");
                LOG.debug(sb.toString());
            }

            DirectoryEntry root = fs.getRoot();
            if (LOG.isDebugEnabled()) {
                LOG.debug("root: " + root);
            }
            
            if (root.hasEntry("\05DigitalSignature") ||
                root.hasEntry("\05MsiDigitalSignatureEx")) {
                throw new IllegalRequestException("MSI package already signed");
            }

            MessageDigest md = MessageDigest.getInstance(digestAlgorithm.name());
            
            // Calculate digest over all files
            MSIUtils.traverseDirectory(fs, root, md);
            final byte[] messageDigest = md.digest();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Message Digest: " + Hex.toHexString(messageDigest));
            }

            SpcSipInfo sipInfo = new SpcSipInfo(new ASN1Integer(1), 
                    new DEROctetString(new byte[] {(byte) 0xf1, (byte) 0x10, (byte) 0x0c, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0xc0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x46}), 
                    new ASN1Integer(0), 
                    new ASN1Integer(0), 
                    new ASN1Integer(0), 
                    new ASN1Integer(0), 
                    new ASN1Integer(0));

            SpcIndirectDataContent idc = new SpcIndirectDataContent(new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID, sipInfo), new DigestInfo(new AlgorithmIdentifier(digestAlgorithm.oid), messageDigest));

            final DigestCalculatorProvider calcProvider =
                    new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();

            final AuthenticodeSignedDataGenerator generator
                    = new AuthenticodeSignedDataGenerator();
            // prepare the authenticated attributes
            CMSAttributeTableGenerator attributeTableGenerator =
                    new DefaultSignedAttributeTableGenerator(createAuthenticatedAttributes(requestContext));
            // prepare the signerInfo with the extra authenticated attributes
            JcaSignerInfoGeneratorBuilder sigBuilder =
                    new JcaSignerInfoGeneratorBuilder(calcProvider);
            sigBuilder.setSignedAttributeGenerator(attributeTableGenerator);
      
            final ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg).setProvider(cryptoInstance.getProvider()).build(privateKey);
            generator.addSignerInfoGenerator(sigBuilder.build(contentSigner, cert));
            generator.addCertificates(new JcaCertStore(certs));

            CMSSignedData signedData2 = generator.generate(AuthenticodeObjectIdentifiers.SPC_INDIRECT_DATA_OBJID, idc);

            if (tsaURL != null || tsaWorker != null) {
                final Timestamper timestamper = createTimestamper(requestContext);
                
                if (tsaURL != null) {
                    timestamper.setURL(tsaURL);
                }
                
                signedData2 = timestamper.timestamp(digestAlgorithm, signedData2);
            }

            final byte[] signedbytes = signedData2.toASN1Structure().getEncoded("DER");
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("Version: " + signedData2.getVersion());
                LOG.debug("Size: " + signedbytes.length);
            }

            try (final NPOIFSFileSystem fsOut =
                    new NPOIFSFileSystem(responseData.getAsFile(), false)) {
                // Add the signature file
                fsOut.createDocument(new ByteArrayInputStream(signedbytes), "\05DigitalSignature");

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

                return new SignatureResponse(sReq.getRequestID(), responseData, cert,
                                             archiveId, archivables,
                                             RESPONSE_CONTENT_TYPE);
            }
        } catch (OperatorCreationException | CertificateEncodingException | CMSException | NoSuchAlgorithmException ex) {
                throw new SignServerException("Error signing", ex);
        }
    }
    
    /**
     * Creates the authenticated attributes for the SignerInfo section of the signature.
     */
    private AttributeTable createAuthenticatedAttributes(final RequestContext requestContext)
        throws IllegalRequestException {
        List<Attribute> attributes = new ArrayList<>();
        
        SpcStatementType spcStatementType = new SpcStatementType(AuthenticodeObjectIdentifiers.SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID);
        attributes.add(new Attribute(AuthenticodeObjectIdentifiers.SPC_STATEMENT_TYPE_OBJID, new DERSet(spcStatementType)));
        
        String programNameToUse = programName;
        String programURLToUse = programURL;
        final String requestedName = RequestMetadata.getInstance(requestContext).get(PROGRAM_NAME);
        final String requestedURL = RequestMetadata.getInstance(requestContext).get(PROGRAM_URL);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Configured programName: " + programName + ", configured programURL: " + programURL
                    + "\nRequested programName: " + requestedName + ", requested programURL: " + requestedURL);
        }

        if (requestedName != null) {
            if (allowProgramNameOverride) {
                if (requestedName.trim().isEmpty()) { // Treat empty as removal of name
                    programNameToUse = null;
                } else {
                    programNameToUse = requestedName;
                }
            } else {
                throw new IllegalRequestException("Requesting PROGRAM_NAME not allowed.");
            }
        }

        if (requestedURL != null) {
            if (allowProgramURLOverride) {
                if (requestedURL.trim().isEmpty()) { // Treat empty as removal of name
                    programURLToUse = null;
                } else {
                    programURLToUse = requestedURL;
                }
            } else {
                throw new IllegalRequestException("Requesting PROGRAM_URL not allowed.");
            }
        }
        
        if (programNameToUse != null || programURLToUse != null) {
            SpcSpOpusInfo spcSpOpusInfo =
                    new SpcSpOpusInfo(programNameToUse, programURLToUse);
            attributes.add(new Attribute(AuthenticodeObjectIdentifiers.SPC_SP_OPUS_INFO_OBJID, new DERSet(spcSpOpusInfo)));
        }
        
        return new AttributeTable(new DERSet(attributes.toArray(new ASN1Encodable[attributes.size()])));
    }
    
    private NPOIFSFileSystem createFileSystem(ReadableData requestData,
                                              final boolean readOnly) throws IOException {
        final NPOIFSFileSystem result;
        /* This does not work: an exception is throwed at end of file, maybe because it is openned read-only */
        if (requestData.isFile()) {
            result = new NPOIFSFileSystem(requestData.getAsFile(), readOnly);
        } else {
            result = new NPOIFSFileSystem(requestData.getAsInputStream());
            
            
        }
        return result;
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

            if (!pe.getSignatures().isEmpty()) {
                throw new IllegalRequestException("Portable executable already signed");
            }

            final PESigner signer = new PESigner(includedCertificates(certs).toArray(new Certificate[0]), privKey);
            
            if (tsaURL != null || tsaWorker != null) {
                final Timestamper timestamper = createTimestamper(requestContext);

                signer.withTimestamping(true);
                signer.withTimestamper(timestamper);
            
                if (tsaURL != null) {
                    signer.withTimestampingAutority(tsaURL);
                }
            } else {
                signer.withTimestamping(false);
            }
            
            if (programName != null) {
                signer.withProgramName(programName);
            }
            if (programURL != null) {
                signer.withProgramURL(programURL);
            }
            
            final String requestedName = RequestMetadata.getInstance(requestContext).get(PROGRAM_NAME);
            final String requestedURL = RequestMetadata.getInstance(requestContext).get(PROGRAM_URL);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Configured programName: " + programName + ", configured programURL: " + programURL
                        + "\nRequested programName: " + requestedName + ", requested programURL: " + requestedURL);
            }
            
            if (requestedName != null) {
                if (allowProgramNameOverride) {
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
                if (allowProgramURLOverride) {
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

            try {
                signer.sign(pe, sigAlg);
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
     * @param file
     * @return file type (PE or MSI)
     */
    private FileType getTypeOfFile(final InputStream in)
        throws FileNotFoundException, IOException {
        
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
                        new ExternalRFC3161Timestamper(tsaUsername,
                                                       tsaPassword);
                } else {
                    timestamper =
                        new InternalRFC3161Timestamper(tsaWorker,
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
    
    private static byte[] fetchTimestampExternal(byte[] request,
                                                 URL tsaurl,
                                                 String basicAuthorization,
                                                 String contentType,
                                                 String acceptType)
        throws IOException, CMSException {
        HttpURLConnection conn = (HttpURLConnection) tsaurl.openConnection();
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setUseCaches(false);
        conn.setRequestMethod("POST");
        if (basicAuthorization != null) {
            conn.setRequestProperty("Authorization", "Basic " + basicAuthorization);
        }
        conn.setRequestProperty("Content-type", contentType);
        conn.setRequestProperty("Content-length", String.valueOf(request.length));
        conn.setRequestProperty("Accept", acceptType);
        conn.setRequestProperty("User-Agent", "Transport");

        conn.getOutputStream().write(request);
        conn.getOutputStream().flush();

        if (conn.getResponseCode() >= 400) {
            throw new IOException("Unable to complete the timestamping due to HTTP error: " + conn.getResponseCode() + " - " + conn.getResponseMessage());
        }

        InputStream in = conn.getInputStream();
        ByteArrayOutputStream bout = new ByteArrayOutputStream();

        byte[] buffer = new byte[4096];
        int n;
        while ((n = in.read(buffer)) != -1) {
            bout.write(buffer, 0, n);
        }

        byte[] response = bout.toByteArray();

        return response;
    }
    
    private static CMSSignedData responseToAuthcodeTimestamp(byte[] response) throws CMSException {
        return new CMSSignedData(Base64.decode(response));
    }
    
    private static CMSSignedData responseToRFCTimestamp(byte[] response,
            TimeStampRequest req) throws TSPException, IOException {
        TimeStampResp resp = TimeStampResp.getInstance(response);
        TimeStampResponse tsr = new TimeStampResponse(resp);
        tsr.validate(req);
        if (tsr.getStatus() != 0) {
            throw new IOException("Unable to complete the timestamping due to an invalid response (" + tsr.getStatusString() + ")");
        }

        return tsr.getTimeStampToken().toCMSSignedData();
    }
    

    public static class InternalAuthenticodeTimestamper extends AuthenticodeTimestamper {

        private final String workerNameOrId;
        private final String username;
        private final String password;
        private final InternalProcessSessionLocal workerSession;
        
        private final File fileRepository = new UploadConfig().getRepository();

        public InternalAuthenticodeTimestamper(final String tsaWorkerNameOrId,
                                               final String username,
                                               final String password,
                                               final InternalProcessSessionLocal workerSession) {
            this.workerNameOrId = tsaWorkerNameOrId;
            this.username = username;
            this.password = password;
            this.workerSession = workerSession;
        }
        
        @Override
        protected CMSSignedData timestamp(DigestAlgorithm algo, byte[] encryptedDigest) throws IOException, TimestampingException {
            AuthenticodeTimeStampRequest timestampRequest = new AuthenticodeTimeStampRequest(encryptedDigest);
            byte[] request = Base64.encode(timestampRequest.getEncoded("DER"));
            
            try {
                return responseToAuthcodeTimestamp(fetchTimestampInternal(request, workerNameOrId, username,
                                          password, hashCode(), workerSession,
                                          fileRepository));
            } catch (CMSException ex) {
                throw new TimestampingException("Failed to timestamp", ex);
            }
        }
    }
    
    public static class InternalRFC3161Timestamper extends RFC3161Timestamper {

        private final String workerNameOrId;
        private final String username;
        private final String password;
        private final InternalProcessSessionLocal workerSession;

        private final File fileRepository = new UploadConfig().getRepository();

        public InternalRFC3161Timestamper(final String tsaWorkerNameOrId,
                                          final String username,
                                          final String password,
                                          final InternalProcessSessionLocal workerSession) {
            this.workerNameOrId = tsaWorkerNameOrId;
            this.username = username;
            this.password = password;
            this.workerSession = workerSession;
        }
        
        @Override
        protected CMSSignedData timestamp(DigestAlgorithm algo, byte[] encryptedDigest) throws IOException, TimestampingException {
            TimeStampRequestGenerator reqgen = new TimeStampRequestGenerator();
            reqgen.setCertReq(true);
            TimeStampRequest req = reqgen.generate(algo.oid, algo.getMessageDigest().digest(encryptedDigest));
            byte request[] = req.getEncoded();

            try {
                return responseToRFCTimestamp(fetchTimestampInternal(request, workerNameOrId, username,
                        password, hashCode(), workerSession,
                        fileRepository), req);
            } catch (TSPException ex) {
                throw new TimestampingException("Failed to timestamp", ex);
            }
        }
    }
    
    public static class ExternalAuthenticodeTimestamper extends AuthenticodeTimestamper {

        private final String basicAuthorization;

        public ExternalAuthenticodeTimestamper(final String username,
                                               final String password) {
            if (username == null) {
                basicAuthorization = null;
            } else {
                final String usrAndPwd = username + ":" + password;
                basicAuthorization = Base64.toBase64String(usrAndPwd.getBytes());
            }
        }

        @Override
        protected CMSSignedData timestamp(DigestAlgorithm algo, byte[] encryptedDigest) throws IOException, TimestampingException {
            try {
                AuthenticodeTimeStampRequest timestampRequest = new AuthenticodeTimeStampRequest(encryptedDigest);
                
                byte[] request = Base64.encode(timestampRequest.getEncoded("DER"));
                
                return responseToAuthcodeTimestamp(fetchTimestampExternal(request, tsaurl, basicAuthorization,
                                                   "application/octet-stream",
                                                   "application/octet-stream"));
            } catch (CMSException ex) {
                throw new TimestampingException("Failed to timestamp", ex);
            }
        }
    }
    
    public static class ExternalRFC3161Timestamper extends RFC3161Timestamper {
        private final String basicAuthorization;

        public ExternalRFC3161Timestamper(final String username,
                                          final String password) {
            if (username == null) {
                basicAuthorization = null;
            } else {
                final String usrAndPwd = username + ":" + password;
                basicAuthorization = Base64.toBase64String(usrAndPwd.getBytes());
            }
        }
        
        @Override
        protected CMSSignedData timestamp(DigestAlgorithm algo, byte[] encryptedDigest) throws IOException, TimestampingException {
            try {
                TimeStampRequestGenerator reqgen = new TimeStampRequestGenerator();
                reqgen.setCertReq(true);
                TimeStampRequest req = reqgen.generate(algo.oid, algo.getMessageDigest().digest(encryptedDigest));
                byte request[] = req.getEncoded();
                
                return responseToRFCTimestamp(fetchTimestampExternal(request, tsaurl, basicAuthorization,
                                                                     "application/timestamp-query",
                                                                     "application/timestamp-reply"),
                                              req);
            } catch (TSPException | CMSException ex) {
                throw new TimestampingException("Failed to timestamp", ex);
            }
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
