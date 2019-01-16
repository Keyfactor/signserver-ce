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
package org.signserver.module.pdfsigner;

import com.lowagie.text.DocumentException;
import com.lowagie.text.exceptions.BadPasswordException;
import com.lowagie.text.pdf.*;

import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.persistence.EntityManager;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.cesecore.util.CertTools;
import org.signserver.common.*;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.server.IServices;
import org.signserver.server.UsernamePasswordClientCredential;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;
import org.signserver.server.signers.BaseSigner;
import org.signserver.server.statistics.Event;
import org.signserver.validationservice.server.ValidationUtils;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;

/**
 * A Signer signing PDF files using the IText PDF library.
 *
 * Implements a ISigner and have the following properties: REASON = The reason
 * shown in the PDF signature LOCATION = The location shown in the PDF signature
 * RECTANGLE = The location of the visible signature field (llx, lly, urx, ury)
 *
 * TSA_URL = The URL of the timestamp authority TSA_USERNAME = Account
 * (username) of the TSA TSA_PASSWORD = Password for TSA
 *
 * CERTIFICATION_LEVEL = The level of certification for the document.
 * NOT_CERTIFIED, FORM_FILLING_AND_ANNOTATIONS, FORM_FILLING or NOT_CERTIFIED
 * (default: NOT_CERTIFIED).
 *
 * REFUSE_DOUBLE_INDIRECT_OBJECTS = True if documents with multiple indirect
 * objects with the same object number and generation number pair should be
 * refused. Used to mitigate a collision signature vulnerability described in 
 * http://pdfsig-collision.florz.de/
 *
 * REJECT_PERMISSIONS: Comma separated list of permissions for which SignServer 
 * will refuse to  sign the document if present. See Permissions for available 
 * permission names.
 *
 * @author Tomas Gustavsson
 * @author Aziz Göktepe
 * @author Markus Kilås
 * @version $Id$
 */
public class PDFSigner extends BaseSigner {

    /** Logger for this class. */
    public static final Logger LOG = Logger.getLogger(PDFSigner.class);
    
    // private final CSVFileStatisticsCollector cSVFileStatisticsCollector =
    // CSVFileStatisticsCollector.getInstance(this.getClass().getName(),
    // "PDF size in bytes");
    
    // Configuration Property constants
    // signature properties
    public static final String REASON = "REASON";
    public static final String REASONDEFAULT = "Signed by SignServer";
    public static final String LOCATION = "LOCATION";
    public static final String LOCATIONDEFAULT = "SignServer";
    
    // properties that control signature visibility
    public static final String ADD_VISIBLE_SIGNATURE = "ADD_VISIBLE_SIGNATURE";
    public static final boolean ADD_VISIBLE_SIGNATURE_DEFAULT = false;
    public static final String VISIBLE_SIGNATURE_PAGE = "VISIBLE_SIGNATURE_PAGE";
    public static final String VISIBLE_SIGNATURE_PAGE_DEFAULT = "First";
    public static final String VISIBLE_SIGNATURE_RECTANGLE = "VISIBLE_SIGNATURE_RECTANGLE";
    public static final String VISIBLE_SIGNATURE_RECTANGLE_DEFAULT = "400,700,500,800";
    public static final String VISIBLE_SIGNATURE_CUSTOM_IMAGE_BASE64 = "VISIBLE_SIGNATURE_CUSTOM_IMAGE_BASE64";
    public static final String VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH = "VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH";
    public static final String VISIBLE_SIGNATURE_CUSTOM_IMAGE_SCALE_TO_RECTANGLE = "VISIBLE_SIGNATURE_CUSTOM_IMAGE_RESIZE_TO_RECTANGLE";
    public static final boolean VISIBLE_SIGNATURE_CUSTOM_IMAGE_SCALE_TO_RECTANGLE_DEFAULT = true;
    public static final String CERTIFICATION_LEVEL = "CERTIFICATION_LEVEL";
    public static final int CERTIFICATION_LEVEL_DEFAULT = PdfSignatureAppearance.NOT_CERTIFIED;
    
    // properties that control timestamping of signature
    public static final String TSA_URL = "TSA_URL";
    public static final String TSA_USERNAME = "TSA_USERNAME";
    public static final String TSA_PASSWORD = "TSA_PASSWORD";
    public static final String TSA_WORKER = "TSA_WORKER";
    public static final String TSA_DIGESTALGORITHM = "TSA_DIGESTALGORITHM";
    
    // extra properties
    public static final String EMBED_CRL = "EMBED_CRL";
    public static final boolean EMBED_CRL_DEFAULT = false;
    public static final String EMBED_OCSP_RESPONSE = "EMBED_OCSP_RESPONSE";
    public static final boolean EMBED_OCSP_RESPONSE_DEFAULT = false;
    
    /** Used to mitigate a collision signature vulnerability described in http://pdfsig-collision.florz.de/ */
    public static final String REFUSE_DOUBLE_INDIRECT_OBJECTS = "REFUSE_DOUBLE_INDIRECT_OBJECTS";
    
    // Permissions properties
    /** List of permissions for which SignServer will refuse to sign the document if present. **/
    public static final String REJECT_PERMISSIONS = "REJECT_PERMISSIONS";
    /** List of permissions to set (all other are cleared). **/
    public static final String SET_PERMISSIONS = "SET_PERMISSIONS";
    /** List of permissions to remove (all other existing permissions are left untouched). **/
    public static final String REMOVE_PERMISSIONS = "REMOVE_PERMISSIONS";
    /** Future property with list of permissions to add). **/
    // public static final String ADD_PERMISSIONS = "ADD_PERMISSIONS";
    /** Password to set as owner password. */
    public static final String SET_OWNERPASSWORD = "SET_OWNERPASSWORD";
    
    // archivetodisk properties
    public static final String PROPERTY_ARCHIVETODISK = "ARCHIVETODISK";
    public static final String PROPERTY_ARCHIVETODISK_PATH_BASE = "ARCHIVETODISK_PATH_BASE";
    public static final String PROPERTY_ARCHIVETODISK_PATH_PATTERN = "ARCHIVETODISK_PATH_PATTERN";
    public static final String PROPERTY_ARCHIVETODISK_FILENAME_PATTERN = "ARCHIVETODISK_FILENAME_PATTERN";

    public static final String DEFAULT_ARCHIVETODISK_PATH_PATTERN = "${DATE:yyyy/MM/dd}";
    public static final String DEFAULT_ARCHIVETODISK_FILENAME_PATTERN = "${WORKERID}-${REQUESTID}-${DATE:HHmmssSSS}.pdf";

    private static final String ARCHIVETODISK_PATTERN_REGEX =
            "\\$\\{(.+?)\\}";
    private static final String CONTENT_TYPE = "application/pdf";

    public static final String DIGESTALGORITHM = "DIGESTALGORITHM";
    private static final String DEFAULTDIGESTALGORITHM = "SHA256";
    
    private static final String DEFAULT_TSA_DIGESTALGORITHM = "SHA256";
    
    private Pattern archivetodiskPattern;

    /** Random used for instance when setting a random owner/permissions password*/
    private SecureRandom random = new SecureRandom();
    
    private List<String> configErrors;

    private InternalProcessSessionLocal workerSession;

    private String digestAlgorithm = DEFAULTDIGESTALGORITHM;

    /* TODO: for now these are two separate fields since there are different
     * APIs handling TSA digests. Maybe this should be handled in the 
     * PDFParameters utility class.
     */
    private ASN1ObjectIdentifier tsaDigestAlgorithm;
    private String tsaDigestAlgorithmName; // passed to PdfPkcs7
    PDFSignerParameters params;
    
    @Override
    public void init(int signerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEntityManager) {
        super.init(signerId, config, workerContext, workerEntityManager);

        configErrors = new LinkedList<>();
        
        // Check properties for archive to disk
        if (StringUtils.equalsIgnoreCase("TRUE",
                config.getProperty(PROPERTY_ARCHIVETODISK, Boolean.FALSE.toString()))) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Archiving to disk");
            }

            final String path = config.getPropertyThatCouldBeEmpty(PROPERTY_ARCHIVETODISK_PATH_BASE);
            if (path == null) {
                LOG.warn("Worker[" + workerId
                        + "]: Archiving path missing");
                configErrors.add("Archiving path not specified");
            } else if (!new File(path).exists()) {
                LOG.warn("Worker[" + workerId
                        + "]: Archiving path does not exists: "
                        + path);
            }
        }
        archivetodiskPattern = Pattern.compile(ARCHIVETODISK_PATTERN_REGEX);
        
        digestAlgorithm = config.getProperty(DIGESTALGORITHM, DEFAULTDIGESTALGORITHM);
        tsaDigestAlgorithmName = config.getProperty(TSA_DIGESTALGORITHM,
                                                DEFAULT_TSA_DIGESTALGORITHM);
        final DefaultDigestAlgorithmIdentifierFinder algFinder =
                new DefaultDigestAlgorithmIdentifierFinder();
        final AlgorithmIdentifier ai = algFinder.find(tsaDigestAlgorithmName);
        
        tsaDigestAlgorithm = ai.getAlgorithm();
        
        if (tsaDigestAlgorithm == null) {
            configErrors.add("Illegal timestamping digest algorithm specified: " +
                             tsaDigestAlgorithmName);
        }
        
        boolean algorithmSupported = PdfSignatureDigestAlgorithms.isSupported(digestAlgorithm);
        if (!algorithmSupported) {
           configErrors.add("Illegal digest algorithm: " + digestAlgorithm); 
        }
        
        // additionally check that at least one certificate is included, assumed by iText
        // (initIncludeCertificateLevels already checks non-negative values)
        if (hasSetIncludeCertificateLevels && includeCertificateLevels == 0) {
            configErrors.add("Illegal value for property " + WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS + ". Only numbers >= 1 supported.");
        }
        
        // check that TSA_URL and TSA_WORKER is not set at the same time
        if (config.getProperty(TSA_URL, DEFAULT_NULL) != null && config.getProperty(TSA_WORKER, DEFAULT_NULL) != null) {
            configErrors.add("Can not specify " + TSA_URL + " and " + TSA_WORKER + " at the same time.");
        }

        // retrieve and preprocess configuration parameter values
        params = new PDFSignerParameters(workerId, config, configErrors);

    }

    
    
    @Override
    protected List<String> getCryptoTokenFatalErrors(final IServices services) {
        final List<String> errors = super.getCryptoTokenFatalErrors(services);
        
        // according to the PDF specification, only SHA1 is permitted as digest algorithm
        // for DSA public/private keys
        final RequestContext context = new RequestContext(true);
        context.setServices(services);
        ICryptoInstance crypto = null;
        try {
            final ICryptoTokenV4 token = getCryptoToken(services);    
            crypto = acquireDefaultCryptoInstance(context);

            if (token != null) {
                final PublicKey pub = crypto.getPublicKey();
                final PrivateKey priv = crypto.getPrivateKey();
                
                if (pub instanceof DSAPublicKey || priv instanceof DSAPrivateKey) {
                    if (!"SHA1".equals(digestAlgorithm)) {
                        errors.add("Only SHA1 is permitted as digest algorithm for DSA public/private keys");
                    }
                }
            }
        } catch (CryptoTokenOfflineException | SignServerException | InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter | IllegalRequestException e) { // NOPMD
            // In this case, we can't tell if the keys are DSA
            // appropriate crypto token errors should be handled by the base class
        } finally {
            if (crypto != null) {
                try {
                    releaseCryptoInstance(crypto, context);
                } catch (SignServerException ex) {
                    LOG.warn("Unable to release crypto instance", ex);
                }
            }
        }

        return errors;
    }



    /**
     * The main method performing the actual signing operation. Expects the
     * signRequest to be a GenericSignRequest containing a signed PDF file.
     * 
     * @param signRequest
     * @param requestContext
     * @return 
     * @throws IllegalRequestException 
     * @throws SignServerException
     * @throws CryptoTokenOfflineException
     * @see org.signserver.server.IProcessable#processData(org.signserver.common.ProcessRequest,
     *      org.signserver.common.RequestContext)
     */
    @Override
    public Response processData(Request signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {        
        if (!(signRequest instanceof SignatureRequest)) {
            throw new IllegalRequestException(
                    "Received request wasn't an expected GenericSignRequest.");
        }
        
        if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }
        
        final SignatureRequest sReq = (SignatureRequest) signRequest;
        final String archiveId = createArchiveId(new byte[0], (String) requestContext.get(RequestContext.TRANSACTION_ID));
        final ReadableData requestData = sReq.getRequestData();

        // Log values
        final LogMap logMap = LogMap.getInstance(requestContext);        

        // Start processing the actual signature
        
        if (requestContext.get(RequestContext.STATISTICS_EVENT) != null) {
            Event event = (Event) requestContext.get(RequestContext.STATISTICS_EVENT);
            event.addCustomStatistics("PDFBYTES", (int) sReq.getRequestData().getLength());
        }
        
        ICryptoInstance crypto = null;
        try {
            crypto = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, signRequest, requestContext);

            // Get the data as file or byte array
            final File pdfFile;
            final byte[] pdfBytes;
            if (requestData.isFile()) {
                pdfFile = requestData.getAsFile();
                pdfBytes = null;
            } else {
                pdfFile = null;
                pdfBytes = requestData.getAsByteArray();
            }
            final WritableData responseData = sReq.getResponseData();
            
            if (params.isRefuseDoubleIndirectObjects()) {
                checkForDuplicateObjects(pdfBytes != null ? new PRTokeniser(pdfBytes) : new PRTokeniser(pdfFile.getAbsolutePath()));
            }

            // Get the password to open the PDF with
            final byte[] password = getPassword(requestContext);
            if (password == null || password.length == 0) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Password was null or empty");
                }
                logMap.put(IWorkerLogger.LOG_PDF_PASSWORD_SUPPLIED,
                           new Loggable() {
                               @Override
                               public String toString() {
                                   return Boolean.FALSE.toString();
                               }
                           });
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Password length was " + password.length + " bytes");
                }
                logMap.put(IWorkerLogger.LOG_PDF_PASSWORD_SUPPLIED,
                           new Loggable() {
                               @Override
                               public String toString() {
                                   return Boolean.TRUE.toString();
                               }
                           });
            }
            
            addSignatureToPDFDocument(crypto, params, pdfBytes, pdfFile, password, 0,
                                              signRequest, responseData, requestContext, tsaDigestAlgorithm, tsaDigestAlgorithmName);
            final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, responseData.toReadableData(), archiveId));
            
            
            

            // Archive to disk
            if (StringUtils.equalsIgnoreCase("TRUE",
                    config.getProperty(PROPERTY_ARCHIVETODISK, Boolean.FALSE.toString()))) {
                archiveToDisk(sReq, responseData.toReadableData(), requestContext);
            }
            
            // The client can be charged for the request
            requestContext.setRequestFulfilledByWorker(true);
            
            
            return new SignatureResponse(sReq.getRequestID(),
                    responseData,
                    getSigningCertificate(crypto),
                    archiveId, archivables, CONTENT_TYPE);
        } catch (DocumentException e) {
            throw new IllegalRequestException("Could not sign document: "
                    + e.getMessage(), e);
        } catch (BadPasswordException ex) {
            throw new IllegalRequestException("A valid password is required to sign the document: " + ex.getMessage(), ex);
        } catch (UnsupportedEncodingException ex) {
            throw new IllegalRequestException("The supplied password could not be read: " + ex.getMessage(), ex);
        } catch (IOException e) {
            // fallback for IOException
            throw new IllegalRequestException("Could not sign document: "
                    + e.getMessage(), e);
        } finally {
            releaseCryptoInstance(crypto, requestContext);
        }
    }

    /**
     * Calculates an estimate of the PKCS#7 structure size given the provided  
     * input parameters.
     *
     * Questions that we need to answer to construct an formula for calculating 
     * a good enough estimate:
     *
     * 1. What are the parameters influencing the PKCS#7 size?
     *    - static or depending on algorithms: PKCS#7 signature size, 
     *    - Certificates list
     *    - CRL list
     *    - OCSP bytes
     *    - timestamp response
     *
     * 2. How much does the size increase when the size of an certificate increases?
     *    - It appears to be at maximum the same increase in size
     *
     * 3. How much does the size increase for each new certificate, not including the certificate size?
     *    - 0. No increase for each certificate except the actual certificate size
     *
     * 4. How much does the size increase when the size of the timestamp responses increases?
     *    - It appears to be at maximum the same increase in size
     *    - However as the response is sent after the signing and possibly 
     *      from an external server we can not be sure about what size it 
     *      will have. We should use a large enough (but reasonable) value that 
     *      it is not so likely that we will have to do a second try.
     * 
     * 5. How much does the size increase when the size of an CRL increases?
     *    - It appears to be the same increase in size most of the times but in
     *      in one case it got 1 byte larger.
     *    - It turns out that the CRLs are included twice (!)
     *    
     * 6. How much does the size increase for each new CRL, not including the CRL size?
     *    - 0. No increase for each CRL except the actual CRL size
     *
     * 7. What is a typical size of an timestamp response?
     *    - That depends mostly on the included certificate chain
     *
     * 8. What value should we use in the initial estimate for the timestamp?
     *    - Currently 4096 is used but with a chain of 4 "normal" certificates
     *      that is a little bit too little.
     *    - Lets use 7168 and there are room for about 6 "normal" certificates
     * 
     * 
     * See also PDFSignerUnitTest for tests that the answers to the questions 
     * above still holds.
     * @param certChain The signing certificate chain
     * @param tsc Timestamp client, this can be null if no timestamp response is used. The contribution is estimated by using a fixed value
     * @param ocsp The OCSP response, can be null
     * @param crlList The list of CRLs included in the signature, this can be null
     * 
     * @return Returns the estimated signature size in bytes
     */
    protected int calculateEstimatedSignatureSize(Certificate[] certChain, TSAClient tsc,
    		byte[] ocsp, CRL[] crlList) throws SignServerException {
		int estimatedSize = 0;

		if (LOG.isDebugEnabled()) {
			LOG.debug("Calculating estimated signature size");
		}
		
		for (Certificate cert : certChain) {
			try {
				int certSize = cert.getEncoded().length;
				estimatedSize += certSize;
				
				if (LOG.isDebugEnabled()) {
					LOG.debug("Adding " + certSize + " bytes for certificate");
				}
				
			} catch (CertificateEncodingException e) {
				throw new SignServerException("Error estimating signature size contribution for certificate", e);
			}
		}
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("Total size of certificate chain: " + estimatedSize);
		}
		
		// add estimate for PKCS#7 structure + hash
		estimatedSize += 2000;

		// add space for OCSP response
		if (ocsp != null) {
			estimatedSize += ocsp.length;
			
			if (LOG.isDebugEnabled()) {
				LOG.debug("Adding " + ocsp.length + " bytes for OCSP response");
			}
		}
		
		if (tsc != null) {
			// add guess for timestamp response (which we can't really know)
			// TODO: we might be able to store the size of the last TSA response and re-use next time...
			final int tscSize = 4096;
			
			estimatedSize += tscSize;
			
			if (LOG.isDebugEnabled()) {
				LOG.debug("Adding " + tscSize + " bytes for TSA");
			}
		}
	
		// add estimate for CRL
		if (crlList != null) {
			for (CRL crl : crlList) {
				if (crl instanceof X509CRL) {
					X509CRL x509Crl = (X509CRL) crl;
				
					try {
						int crlSize = x509Crl.getEncoded().length;
						// the CRL is included twice in the signature...
						estimatedSize += crlSize * 2;
						
						if (LOG.isDebugEnabled()) {
							LOG.debug("Adding " + crlSize * 2 + " bytes for CRL");
						}
						
					} catch (CRLException e) {
						throw new SignServerException("Error estimating signature size contribution for CRL", e);
					}
				}		
			}
			estimatedSize += 100;
		}

		return estimatedSize;
    }
    
    
    protected byte[] calculateSignature(PdfPKCS7 sgn, int size, MessageDigest messageDigest,
    		Calendar cal, PDFSignerParameters params, Certificate[] certChain, TSAClient tsc, byte[] ocsp,
    		PdfSignatureAppearance sap, String tsaDigestAlgo) throws IOException, DocumentException, SignServerException {
     
        final HashMap<PdfName, Integer> exc = new HashMap<>();
        exc.put(PdfName.CONTENTS, size * 2 + 2);
        sap.preClose(exc);


        InputStream data = sap.getRangeStream();

        byte buf[] = new byte[8192];
        int n;
        while ((n = data.read(buf)) > 0) {
            messageDigest.update(buf, 0, n);
        }
        byte hash[] = messageDigest.digest();
        

        byte sh[] = sgn.getAuthenticatedAttributeBytes(hash, cal, ocsp);
        try {
            sgn.update(sh, 0, sh.length);
        } catch (SignatureException e) {
            throw new SignServerException("Error calculating signature", e);
        }

        byte[] encodedSig = sgn.getEncodedPKCS7(hash, cal, tsc, ocsp,
                                                tsaDigestAlgo);
        
        return encodedSig;
    }
    
    protected void addSignatureToPDFDocument(final ICryptoInstance crypto, PDFSignerParameters params,
            byte[] pdfBytes, File pdfFile, byte[] password, int contentEstimated,
            final Request request, final WritableData responseData, final RequestContext context,
            final ASN1ObjectIdentifier tsaDigestAlgo, final String tsaDigestAlgoName)
            throws IOException, DocumentException,
                   CryptoTokenOfflineException, SignServerException, IllegalRequestException {
    	// when given a content length (i.e. non-zero), it means we are running a second try
    	boolean secondTry = contentEstimated != 0;
    	
        // get signing cert certificate chain and private key
        final List<Certificate> certs = getSigningCertificateChain(crypto);
        if (certs == null) {
            throw new SignServerException(
                    "Null certificate chain. This signer needs a certificate.");
        }
        final List<Certificate> includedCerts = includedCertificates(certs);
        Certificate[] certChain = includedCerts.toArray(new Certificate[includedCerts.size()]);
        PrivateKey privKey = crypto.getPrivateKey();

        // need to check digest algorithms for DSA private key at signing
        // time since we can't be sure what key a configured alias selector gives back
        if (privKey instanceof DSAPrivateKey) {
            if (!"SHA1".equals(digestAlgorithm)) {
                throw new IllegalRequestException("Only SHA1 is permitted as digest algorithm for DSA private keys");
            }
        }
        
        final PdfReader reader;
        if (pdfBytes != null) {
            reader = new PdfReader(pdfBytes, password);
        } else {
            reader = new PdfReader(pdfFile.getAbsolutePath(), password);
        }
        boolean appendMode = true; // TODO: This could be good to have as a property in the future

        String strPdfVersion = Character.toString(reader.getPdfVersion());
        PdfVersionCompatibilityChecker pdfVersionCompatibilityChecker = new PdfVersionCompatibilityChecker(strPdfVersion, digestAlgorithm);
            
        if (LOG.isDebugEnabled()) {
            LOG.debug("PDF version: " + strPdfVersion);
        }

        // Don't certify already certified documents
        if (reader.getCertificationLevel() != PdfSignatureAppearance.NOT_CERTIFIED 
                && params.getCertification_level() != PdfSignatureAppearance.NOT_CERTIFIED) {
            throw new IllegalRequestException("Will not certify an already certified document");
        }
        
        // Don't sign documents where the certification does not allow it
        if (reader.getCertificationLevel() == PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED
                || reader.getCertificationLevel() == PdfSignatureAppearance.CERTIFIED_FORM_FILLING) {
            throw new IllegalRequestException("Will not sign a certified document where signing is not allowed");
        }
        
        Permissions currentPermissions = Permissions.fromInt(reader.getPermissions());
        
        if (params.getSetPermissions() != null && params.getRemovePermissions() != null) {
            throw new SignServerException("Signer " + workerId
                    + " missconfigured. Only one of " + SET_PERMISSIONS
                    + " and " + REMOVE_PERMISSIONS + " should be specified.");
        }
        
        Permissions newPermissions;
        if (params.getSetPermissions() != null) {
            newPermissions = params.getSetPermissions();
        } else if (params.getRemovePermissions() != null) {
            newPermissions = currentPermissions.withRemoved(params.getRemovePermissions());
        } else {
            newPermissions = null;
        }
        
        Permissions rejectPermissions = Permissions.fromSet(params.getRejectPermissions());
        byte[] userPassword = reader.computeUserPassword();
        int cryptoMode = reader.getCryptoMode();
        if (LOG.isDebugEnabled()) {
            StringBuilder buff = new StringBuilder();
            buff.append("Current permissions: ").append(currentPermissions).append("\n")
                    .append("Remove permissions: ").append(params.getRemovePermissions()).append("\n")
                    .append("Reject permissions: ").append(rejectPermissions).append("\n")
                    .append("New permissions: ").append(newPermissions).append("\n")
                    .append("userPassword: ").append(userPassword == null ? "null" : "yes").append("\n")
                    .append("ownerPassword: ").append(password == null ? "no" : (isUserPassword(reader, password) ? "no" : "yes")).append("\n")
                    .append("setOwnerPassword: ").append(params.getSetOwnerPassword() == null ? "no" : "yes").append("\n")
                    .append("cryptoMode: ").append(cryptoMode);
            LOG.debug(buff.toString());
        }
        
        if (appendMode && (newPermissions != null || params.getSetOwnerPassword() != null)) {
            appendMode = false;
            if (LOG.isDebugEnabled()) {
                LOG.debug("Changing appendMode to false to be able to change permissions");
            }
        }
        
        OutputStream responseOut = null;
        try {
            // Use stream for in-memory data but use file when we got it as file
            final File responseFile;
            if (pdfFile == null) {
                responseOut = responseData.getAsOutputStream();
                responseFile = null;
            } else {
                responseFile = responseData.getAsFile();
            }

            // increase PDF version if needed by digest algorithm
            final char updatedPdfVersion;
            if (pdfVersionCompatibilityChecker.isVersionUpgradeRequired()) {
                updatedPdfVersion = Character.forDigit(pdfVersionCompatibilityChecker.getMinimumCompatiblePdfVersion(), 10);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Need to upgrade PDF to version 1." + updatedPdfVersion);
                }

                // check that the document isn't already signed 
                // when trying to upgrade version
                final AcroFields af = reader.getAcroFields();
                final List<String> sigNames = af.getSignatureNames();

                if (!sigNames.isEmpty()) {
                    // TODO: in the future we might want to support
                    // a fallback option in this case to allow re-signing using the same version (using append)
                    throw new IllegalRequestException("Can not upgrade an already signed PDF and a higher version is required to support the configured digest algorithm");
                }

                appendMode = false;
            } else {
                updatedPdfVersion = '\0';
            }

            PdfStamper stp = PdfStamper.createSignature(reader, responseOut, updatedPdfVersion, responseFile, appendMode);
            PdfSignatureAppearance sap = stp.getSignatureAppearance();
            
            // Set PDF permissions/encryption if:
            // - there are new permissions or
            // - the owner password has been specified or
            // - if it is not append mode and the crypto mode has been specified (i.e. security mode is on and the PDF needs to be rewritten)
            if (newPermissions != null || params.getSetOwnerPassword() != null || (cryptoMode >= 0 && !appendMode)) {
                if (cryptoMode < 0) {
                    cryptoMode = PdfWriter.STANDARD_ENCRYPTION_128;
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Setting default encryption algorithm");
                    }
                }
                
                if (params.getSetOwnerPassword() != null) {
                    password = params.getSetOwnerPassword().getBytes("ISO-8859-1");
                } else if (isUserPassword(reader, password) && newPermissions != null) {
                    // If we don't have an owner password we might have to get one.
                    // We need to set an owner password if we have new permissions to set otherwise we should not as the original document did not have
                    password = new byte[16];
                    random.nextBytes(password);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Setting random owner password");
                    }
                }
                if (newPermissions == null) {
                    newPermissions = currentPermissions;
                }
                stp.setEncryption(userPassword, password, newPermissions.asInt(), cryptoMode);
                currentPermissions = newPermissions;
            }

            // Reject if any permissions are rejected and the document does not use a permission password
            // or if it contains any of the rejected permissions
            if (rejectPermissions.asInt() != 0) {
                if (cryptoMode < 0 || currentPermissions.containsAnyOf(rejectPermissions)) {
                    throw new IllegalRequestException("Document contains permissions not allowed by this signer");
                }
            }

            // include signer certificate crl inside cms package if requested
            CRL[] crlList = null;
            if (params.isEmbed_crl()) {
                crlList = getCrlsForChain(certs);
            }
            sap.setCrypto(null, certChain, crlList,
                    PdfSignatureAppearance.SELF_SIGNED);

            // add visible signature if requested
            if (params.isAdd_visible_signature()) {
                int signaturePage = getPageNumberForSignature(reader, params);
                sap.setVisibleSignature(new com.lowagie.text.Rectangle(params.getVisible_sig_rectangle_llx(), params.getVisible_sig_rectangle_lly(), params.getVisible_sig_rectangle_urx(), params.getVisible_sig_rectangle_ury()), signaturePage, null);

                // set custom image if requested
                if (params.isUse_custom_image()) {
                    sap.setAcro6Layers(true);
                    PdfTemplate n2 = sap.getLayer(2);
                    params.getCustom_image().setAbsolutePosition(0, 0);
                    n2.addImage(params.getCustom_image());
                }
            }

            // Certification level
            sap.setCertificationLevel(params.getCertification_level());

            PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName(
                    "adbe.pkcs7.detached"));
            dic.setReason(params.getReason());
            dic.setLocation(params.getLocation());
            dic.setDate(new PdfDate(Calendar.getInstance()));

            sap.setCryptoDictionary(dic);

            // add timestamp to signature if requested
            TSAClient tsc = null;
            if (params.isUse_timestamp()) {
                final String tsaUrl = params.getTsa_url();

                if (tsaUrl != null) {
                    tsc = getTimeStampClient(params.getTsa_url(), params.getTsa_username(), params.getTsa_password(),
                                             tsaDigestAlgo);
                } else {
                    tsc = new InternalTSAClient(getProcessSession(context.getServices()),
                            WorkerIdentifier.createFromIdOrName(params.getTsa_worker()), params.getTsa_username(), params.getTsa_password(),
                            tsaDigestAlgo);
                }
            }


            // embed ocsp response in cms package if requested
            // for ocsp request to be formed there needs to be issuer certificate in
            // chain
            byte[] ocsp = null;
            if (params.isEmbed_ocsp_response() && certChain.length >= 2) {
                String url;
                try {
                    url = PdfPKCS7.getOCSPURL((X509Certificate) certChain[0]);
                    if (url != null && url.length() > 0) {
                        ocsp = new OcspClientBouncyCastle(
                                (X509Certificate) certChain[0],
                                (X509Certificate) certChain[1], url).getEncoded();
                    }
                } catch (CertificateParsingException e) {
                    throw new SignServerException(
                            "Error getting OCSP URL from certificate", e);
                }

            }

            PdfPKCS7 sgn;
            try {
                sgn = new PdfPKCS7(privKey, certChain, crlList, digestAlgorithm, null, false);
            } catch (InvalidKeyException | NoSuchProviderException | NoSuchAlgorithmException e) {
                throw new SignServerException("Error constructing PKCS7 package", e);
            }

            MessageDigest messageDigest;
            try {
                messageDigest = MessageDigest.getInstance(digestAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new SignServerException("Error creating " + digestAlgorithm + " digest", e);
            }

            Calendar cal = Calendar.getInstance();

            // calculate signature size
            if (contentEstimated == 0) {
                    contentEstimated =
                            calculateEstimatedSignatureSize(certChain, tsc, ocsp, crlList);
            }

            byte[] encodedSig = calculateSignature(sgn, contentEstimated,
                                                   messageDigest, cal, params,
                                                   certChain, tsc, ocsp, sap,
                                                   tsaDigestAlgoName);

            if (LOG.isDebugEnabled()) {
                    LOG.debug("Estimated size: " + contentEstimated);
                    LOG.debug("Encoded length: " + encodedSig.length);
            }

            if (contentEstimated + 2 < encodedSig.length) {
                    if (!secondTry) {
                            int contentExact = encodedSig.length;
                            LOG.warn("Estimated signature size too small, usinging accurate calculation (resulting in an extra signature computation).");

                            if (LOG.isDebugEnabled()) {
                                    LOG.debug("Estimated size: " + contentEstimated + ", actual size: " + contentExact);
                            }

                            // try signing again
                            addSignatureToPDFDocument(crypto, params, pdfBytes, pdfFile,
                                                             password, contentExact,
                                                             request, responseData, context, tsaDigestAlgo, tsaDigestAlgoName);
                            return;
                    } else {
                            // if we fail to get an accurate signature size on the second attempt, bail out (this shouldn't happen)
                            throw new SignServerException("Failed to calculate signature size");
                    }
            }

            byte[] paddedSig = new byte[contentEstimated];
            System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);

            PdfDictionary dic2 = new PdfDictionary();
            dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
            sap.close(dic2);
            reader.close();

        } finally {
            IOUtils.closeQuietly(responseOut);
        }
    }
    
    protected InternalProcessSessionLocal getProcessSession(IServices services) {
        return services.get(InternalProcessSessionLocal.class);
    }

    /**
     * returns crl list containing crl for each certifcate in crl chain. CRLs
     * are fetched using address specified in CDP.
     * 
     * @return n
     * @throws SignServerException
     */
    private CRL[] getCrlsForChain(final Collection<Certificate> certChain)
            throws SignServerException {

        List<CRL> retCrls = new ArrayList<>();
        for (Certificate currCert : certChain) {
            CRL currCrl = null;
            try {
                URL currCertURL = getCRLDistributionPoint(currCert);
                if (currCertURL == null) {
                    continue;
                }

                currCrl = ValidationUtils.fetchCRLFromURL(currCertURL);

                if (currCrl == null) {
                    throw new SignServerException("Empty CRL file fetched from CDP");
                }
            } catch (CertificateParsingException e) {
                throw new SignServerException(
                        "Error obtaining CDP from signing certificate", e);
            }

            retCrls.add(currCrl);
        }

        if (retCrls.isEmpty()) {
            return null;
        } else {
            return retCrls.toArray(new CRL[retCrls.size()]);
        }

    }

    static URL getCRLDistributionPoint(final Certificate certificate)
            throws CertificateParsingException {
        return CertTools.getCrlDistributionPoint(certificate);
    }

    /**
     * get the page number at which to draw signature rectangle
     * 
     * @param pReader
     * @param pParams
     * @return
     */
    private int getPageNumberForSignature(PdfReader pReader,
            PDFSignerParameters pParams) {
        int totalNumOfPages = pReader.getNumberOfPages();
        if (pParams.getVisible_sig_page().trim().equals("First")) {
            return 1;
        } else if (pParams.getVisible_sig_page().trim().equals("Last")) {
            return totalNumOfPages;
        } else {
            try {
                int pNum = Integer.parseInt(pParams.getVisible_sig_page());
                if (pNum < 1) {
                    return 1;
                } else if (pNum > totalNumOfPages) {
                    return totalNumOfPages;
                } else {
                    return pNum;
                }
            } catch (NumberFormatException ex) {
                // not a numeric argument draw on first line
                return 1;
            }
        }
    }

    private void archiveToDisk(SignatureRequest sReq, ReadableData data, RequestContext requestContext) throws SignServerException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Archiving to disk");
        }

        // Fill in fields that can be used to construct path and filename
        final Map<String, String> fields = new HashMap<>();
        fields.put("WORKERID", String.valueOf(workerId));
        fields.put("WORKERNAME", config.getPropertyThatCouldBeEmpty("NAME"));
        fields.put("REMOTEIP", (String) requestContext.get(RequestContext.REMOTE_IP));
        fields.put("TRANSACTIONID", (String) requestContext.get(RequestContext.TRANSACTION_ID));
        fields.put("REQUESTID", String.valueOf(sReq.getRequestID()));
        fields.put("CUSTOMHEADER1", (String) requestContext.get(RequestContext.X_SIGNSERVER_CUSTOM_1));

        Object credential = requestContext.get(RequestContext.CLIENT_CREDENTIAL);
        if (credential instanceof UsernamePasswordClientCredential) {
            fields.put("USERNAME",
                    ((UsernamePasswordClientCredential) credential).getUsername());
        }

        final String pathFromPattern = formatFromPattern(
                archivetodiskPattern, config.getProperty(
                        PROPERTY_ARCHIVETODISK_PATH_PATTERN,
                        DEFAULT_ARCHIVETODISK_PATH_PATTERN),
                new Date(), fields);

        final File outputPath = new File(new File(config.getPropertyThatCouldBeEmpty(
                PROPERTY_ARCHIVETODISK_PATH_BASE)),
                pathFromPattern);

        if (!outputPath.exists()) {
            if (!outputPath.mkdirs()) {
                LOG.warn("Output path could not be created: "
                        + outputPath.getAbsolutePath());
            }
        }

        final String fileNameFromPattern = formatFromPattern(
                archivetodiskPattern, config.getProperty(
                        PROPERTY_ARCHIVETODISK_FILENAME_PATTERN,
                        DEFAULT_ARCHIVETODISK_FILENAME_PATTERN),
                new Date(), fields);

        final File outputFile = new File(outputPath, fileNameFromPattern);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Worker[" + workerId + "]: Archive to file: "
                    + outputFile.getAbsolutePath());
        }

        try (OutputStream out = new FileOutputStream(outputFile)) {
            IOUtils.copyLarge(data.getAsInputStream(), out);
        } catch (IOException ex) {
            throw new SignServerException(
                    "Could not archive signed document", ex);
        }
    }

    /**
     * Helper method for formatting a text given a set of fields and a date.
     *
     * Sample:
     * "${WORKERID}-${REQUESTID}_${DATE:yyyy-MM-dd}.pdf"
     * Could be:
     * "42-123123123_2010-04-28.pdf"
     * 
     * @param pattern Pre-compiled pattern to use for parsing
     * @param text The text that contains keys to be replaced with values
     * @param date The date to use if date should be inserted
     * @param fields Keys and their values that should be used if they exist in
     * the text.
     * @return The test with keys replaced with values from fields or by
     * formatted date
     * @see java.text.SimpleDateFormat
     */
    static String formatFromPattern(final Pattern pattern, final String text,
            final Date date, final Map<String, String> fields) {
        final String result;

        if (LOG.isDebugEnabled()) {
            LOG.debug("Input string: " + text);
        }

        final StringBuffer sb = new StringBuffer();
        Matcher m = pattern.matcher(text);
        while (m.find()) {
            // when the pattern is ${identifier}, group 0 is 'identifier'
            final String key = m.group(1);

            final String value;
            if (key.startsWith("DATE:")) {
                final FastDateFormat sdf = FastDateFormat.getInstance(
                        key.substring("DATE:".length()).trim());
                value = sdf.format(date);
            } else {
                value = fields.get(key);
            }

            // if the pattern does exists, replace it by its value
            // otherwise keep the pattern ( it is group(0) )
            if (value != null) {
                m.appendReplacement(sb, value);
            } else {
                // I'm doing this to avoid the backreference problem as there will be a $
                // if I replace directly with the group 0 (which is also a pattern)
                m.appendReplacement(sb, "");
                final String unknown = m.group(0);
                sb.append(unknown);
            }
        }
        m.appendTail(sb);
        result = sb.toString();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Result: " + result);
        }
        return result;
    }

    private void checkForDuplicateObjects(PRTokeniser tokens) throws IOException,
            SignServerException {
        if (LOG.isDebugEnabled()) {
            LOG.debug(">checkForDuplicateObjects");
        }
        final Set<String> idents = new HashSet<>();
        final byte[] line = new byte[16];

        while (tokens.readLineSegment(line)) {
            final int[] obj = PRTokeniser.checkObjectStart(line);
            if (obj != null) {
                final String ident = obj[0] + " " + obj[1];

                if (idents.add(ident)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Object: " + ident);
                    }
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Duplicate object: " + ident);
                    }
                    throw new SignServerException("Incorrect document");
                }
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("<checkForDuplicateObjects");
        }
    }

    private static byte[] getPassword(final RequestContext context) throws UnsupportedEncodingException {
        final byte[] result;    
        final String password = RequestMetadata.getInstance(context).get(RequestContext.METADATA_PDFPASSWORD);
        if (password == null) {
            result = null;
        } else {
            result = password.getBytes("ISO-8859-1");
        }
        return result;
    }

    /**
     * @return True if the supplied password is equal to the user password 
     * and thus is not the owner password.
     */
    private boolean isUserPassword(PdfReader reader, byte[] password) {        
        return Arrays.equals(reader.computeUserPassword(), password);
    }

    protected TSAClient getTimeStampClient(String url, String username,
                                             String password,
                                             ASN1ObjectIdentifier digestAlgo) {
        return new TSAClientBouncyCastle(url, username, password, digestAlgo);
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        final List<String> fatalErrors = super.getFatalErrors(services);
        
        fatalErrors.addAll(configErrors);
        return fatalErrors;
    }
    
    /**
     * Internal method for the unit test to set the included certificate levels (to a non-zero value)
     * without having to initializing the signer.
     * 
     * @param includeCertificateLevels
     */
    void setIncludeCertificateLevels(final int includeCertificateLevels) {
        this.includeCertificateLevels = includeCertificateLevels;
    }

}
