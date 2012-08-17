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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.util.CertTools;
import org.signserver.common.ArchiveData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericServletRequest;
import org.signserver.common.GenericServletResponse;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.ISignRequest;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.signers.BaseSigner;
import org.signserver.server.statistics.Event;
import org.signserver.validationservice.server.ValidationUtils;

import com.lowagie.text.DocumentException;
import com.lowagie.text.exceptions.BadPasswordException;
import com.lowagie.text.pdf.OcspClientBouncyCastle;
import com.lowagie.text.pdf.PRTokeniser;
import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignature;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfString;
import com.lowagie.text.pdf.PdfTemplate;
import com.lowagie.text.pdf.PdfWriter;
import com.lowagie.text.pdf.TSAClient;
import com.lowagie.text.pdf.TSAClientBouncyCastle;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang.StringUtils;
import org.signserver.server.UsernamePasswordClientCredential;
import org.signserver.server.log.IWorkerLogger;

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

    private Pattern archivetodiskPattern;

    /** Random used for instance when setting a random owner/permissions password*/
    private SecureRandom random = new SecureRandom();
    
    @Override
    public void init(int signerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEntityManager) {
        super.init(signerId, config, workerContext, workerEntityManager);

        // Check properties for archive to disk
        if (StringUtils.equalsIgnoreCase("TRUE",
                config.getProperty(PROPERTY_ARCHIVETODISK))) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Archiving to disk");
            }

            final String path = config.getProperty(PROPERTY_ARCHIVETODISK_PATH_BASE);
            if (path == null) {
                LOG.warn("Worker[" + workerId
                        + "]: Archiving path missing");
            } else if (!new File(path).exists()) {
                LOG.warn("Worker[" + workerId
                        + "]: Archiving path does not exists: "
                        + path);
            }
        }
        archivetodiskPattern = Pattern.compile(ARCHIVETODISK_PATTERN_REGEX);
    }

    /**
     * The main method performing the actual signing operation. Expects the
     * signRequest to be a GenericSignRequest containing a signed PDF file.
     * 
     * @throws SignServerException
     * @see org.signserver.server.IProcessable#processData(org.signserver.common.ProcessRequest,
     *      org.signserver.common.RequestContext)
     */
    public ProcessResponse processData(ProcessRequest signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {

        ISignRequest sReq = (ISignRequest) signRequest;
        // Check that the request contains a valid GenericSignRequest object
        // with a byte[].
        if (!(signRequest instanceof GenericSignRequest)) {
            throw new IllegalRequestException(
                    "Recieved request wasn't a expected GenericSignRequest.");
        }
        if (!(sReq.getRequestData() instanceof byte[])) {
            throw new IllegalRequestException(
                    "Recieved request data wasn't a expected byte[].");
        }

        // Log values
        final Map<String, String> logMap =
                (Map<String, String>) requestContext.get(RequestContext.LOGMAP);

        // retrieve and preprocess configuration parameter values
        PDFSignerParameters params = new PDFSignerParameters(workerId, config);

        // Start processing the actual signature
        GenericSignResponse signResponse = null;
        byte[] pdfbytes = (byte[]) sReq.getRequestData();
        byte[] fpbytes = CertTools.generateSHA1Fingerprint(pdfbytes);
        String fp = new String(Hex.encode(fpbytes));
        if (requestContext.get(RequestContext.STATISTICS_EVENT) != null) {
            Event event = (Event) requestContext.get(RequestContext.STATISTICS_EVENT);
            event.addCustomStatistics("PDFBYTES", pdfbytes.length);
        }
        try {

            if (params.isRefuseDoubleIndirectObjects()) {
                checkForDuplicateObjects(pdfbytes);
            }

            // Get the password to open the PDF with
            final byte[] password = getPassword(requestContext);
            if (password == null || password.length == 0) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Password was null or empty");
                }
                logMap.put(IWorkerLogger.LOG_PDF_PASSWORD_SUPPLIED, Boolean.FALSE.toString());
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Password length was " + password.length + " bytes");
                }
                logMap.put(IWorkerLogger.LOG_PDF_PASSWORD_SUPPLIED, Boolean.TRUE.toString());
            }
            
            byte[] signedbytes = addSignatureToPDFDocument(params, pdfbytes, password, false);
            if (signRequest instanceof GenericServletRequest) {
                signResponse = new GenericServletResponse(sReq.getRequestID(),
                        signedbytes, getSigningCertificate(), fp,
                        new ArchiveData(signedbytes), "application/pdf");
            } else {
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        signedbytes, getSigningCertificate(), fp,
                        new ArchiveData(signedbytes));
            }

            // Archive to disk
            if (StringUtils.equalsIgnoreCase("TRUE",
                    config.getProperty(PROPERTY_ARCHIVETODISK))) {
                archiveToDisk(sReq, signedbytes, requestContext);
            }
        } catch (DocumentException e) {
            throw new IllegalRequestException("Could not sign document: "
                    + e.getMessage(), e);
        } catch (BadPasswordException ex) {
            throw new IllegalRequestException("A valid password is required to sign the document: " + ex.getMessage(), ex);
        } catch (UnsupportedEncodingException ex) {
            throw new IllegalRequestException("The supplied password could not be read: " + ex.getMessage(), ex);
        } catch (IOException e) {
            throw new IllegalRequestException("Could not sign document: " + e.getMessage(), e);
        }

        return signResponse;
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
     *    
     * 6. How much does the size increase for each new CRL, not including the CRL size?
     *    - 0. No increase for each CRL except the actual CRL size
     *
     * 7. What is a typical size of an timestamp response?
     *    - TODO
     * 8. What value should we use in the initial estimate for the timestamp?
     *    - TODO: Currently 4096 is used
     * 
     * 
     * See also PDFSignerUnitTest for tests that the answers to the questions 
     * above still holds.
     * 
     * 
     * 
     * @param exact Setting this to true to calculate the actual signature size by
     *              using a fake hash value (might cause an extra signature computation)
     * @param sgn
     * @param messageDigest
     * @param cal
     * @param params
     * @param certChain
     * @param tsc
     * @param ocsp
     * @return
     */
    protected int calculateEstimatedSignatureSize(boolean exact, PdfPKCS7 sgn, MessageDigest messageDigest,
    		Calendar cal, PDFSignerParameters params,
    		Certificate[] certChain, TSAClient tsc, byte[] ocsp) {
    	
    	if (exact) {
    		int digestSize = messageDigest.getDigestLength();
    		// fake a hash
    		byte[] hash = new byte[digestSize];
    		byte[] encoded  = sgn.getEncodedPKCS7(hash, cal, tsc, ocsp);

    		return encoded.length;
    	} else {
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
    				
    			}
    		}
    		
    		if (LOG.isDebugEnabled()) {
    			LOG.debug("Total size of certificate chain: " + estimatedSize);
    		}
    		
    		// add some padding here (need to figure out if this depends on hash size
    		// and so on...)
    		estimatedSize += 1000;
	
    		// add space for OCSP response
    		if (ocsp != null) {
    			estimatedSize += ocsp.length * 2;
    		}
    		
    		if (tsc != null) {
    			// add estimated ts token size plus some safety padding
    			estimatedSize += tsc.getTokenSizeEstimate() + 100;
    		}
    	
    		return estimatedSize;
    	}
    }
    
    
    protected byte[] calculateSignature(PdfPKCS7 sgn, int size, MessageDigest messageDigest,
    		Calendar cal, PDFSignerParameters params, Certificate[] certChain, TSAClient tsc, byte[] ocsp,
    		PdfSignatureAppearance sap) throws IOException, DocumentException, SignServerException {
     
        HashMap exc = new HashMap();
        exc.put(PdfName.CONTENTS, new Integer(size * 2 + 2));
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

        byte[] encodedSig = sgn.getEncodedPKCS7(hash, cal, tsc, ocsp);
        
        return encodedSig;
    }
    
    protected byte[] addSignatureToPDFDocument(PDFSignerParameters params,
            byte[] pdfbytes, byte[] password, boolean secondTry) throws IOException, DocumentException,
            CryptoTokenOfflineException, SignServerException, IllegalRequestException {

        // get signing cert certificate chain and private key
        Collection<Certificate> certs = this.getSigningCertificateChain();
        if (certs == null) {
            throw new SignServerException(
                    "Null certificate chain. This signer needs a certificate.");
        }
        Certificate[] certChain = (Certificate[]) certs.toArray(new Certificate[0]);
        PrivateKey privKey = this.getCryptoToken().getPrivateKey(
                ICryptoToken.PURPOSE_SIGN);

        PdfReader reader = new PdfReader(pdfbytes, password);
        boolean appendMode = true; // TODO: This could be good to have as a property in the future

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
        
        ByteArrayOutputStream fout = new ByteArrayOutputStream();
        PdfStamper stp = PdfStamper.createSignature(reader, fout, '\0', null,
                appendMode);
        PdfSignatureAppearance sap = stp.getSignatureAppearance();
        
        // Set the new permissions
        if (newPermissions != null || params.getSetOwnerPassword() != null) {
            if (cryptoMode < 0) {
                cryptoMode = PdfWriter.STANDARD_ENCRYPTION_128;
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Setting default encryption algorithm");
                }
            }
            if (newPermissions == null) {
                newPermissions = currentPermissions;
            }
            if (params.getSetOwnerPassword() != null) {
                password = params.getSetOwnerPassword().getBytes("ISO-8859-1");
            } else if (isUserPassword(reader, password)) {
                // We do not have an owner password so lets use a random one
                password = new byte[16];
                random.nextBytes(password);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Setting random owner password");
                }
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
            crlList = getCrlsForChain(this.getSigningCertificateChain());
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
            tsc = getTimeStampClient(params.getTsa_url(), params.getTsa_username(), params.getTsa_password());
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
            sgn = new PdfPKCS7(privKey, certChain, crlList, "SHA1", null, false);
        } catch (InvalidKeyException e) {
            throw new SignServerException("Error constructing PKCS7 package", e);
        } catch (NoSuchProviderException e) {
            throw new SignServerException("Error constructing PKCS7 package", e);
        } catch (NoSuchAlgorithmException e) {
            throw new SignServerException("Error constructing PKCS7 package", e);
        }

        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new SignServerException("Error creating SHA1 digest", e);
        }
        
        Calendar cal = Calendar.getInstance();
        
        // calculate signature size
        int contentEstimated =
        		calculateEstimatedSignatureSize(false, sgn, messageDigest, cal, params, certChain, tsc,
        				ocsp);

        byte[] encodedSig = calculateSignature(sgn, contentEstimated, messageDigest, cal, params, certChain, tsc, ocsp, sap);

        if (LOG.isDebugEnabled()) {
        	LOG.debug("Estimated size: " + contentEstimated);
        	LOG.debug("Encoded length: " + encodedSig.length);
        }

        if (contentEstimated + 2 < encodedSig.length) {
        	if (!secondTry) {
        		int contentExact = calculateEstimatedSignatureSize(true, sgn, messageDigest, cal, params, certChain, tsc,
    				ocsp);
        		LOG.warn("Estimated signature size too small, usinging accurate calculation (resulting in an extra signature computation).");
        	
        		if (LOG.isDebugEnabled()) {
        			LOG.debug("Estimated size: " + contentEstimated + ", actual size: " + contentExact);
        		}
        	
        		// try signing again
        		return addSignatureToPDFDocument(params, pdfbytes, password, true);
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

        fout.close();
        return fout.toByteArray();
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

        List<CRL> retCrls = new ArrayList<CRL>();
        for (Certificate currCert : certChain) {
            CRL currCrl = null;
            try {
                URL currCertURL = getCRLDistributionPoint(currCert);
                if (currCertURL == null) {
                    continue;
                }

                currCrl = ValidationUtils.fetchCRLFromURL(currCertURL);
            } catch (CertificateParsingException e) {
                throw new SignServerException(
                        "Error obtaining CDP from signing certificate", e);
            }

            retCrls.add(currCrl);
        }

        if (retCrls.isEmpty()) {
            return null;
        } else {
            return retCrls.toArray(new CRL[0]);
        }

    }

    static URL getCRLDistributionPoint(final Certificate certificate)
            throws CertificateParsingException {
        return org.signserver.module.pdfsigner.org.ejbca.util.CertTools.getCrlDistributionPoint(certificate);
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

    private void archiveToDisk(ISignRequest sReq, byte[] signedbytes, RequestContext requestContext) throws SignServerException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Archiving to disk");
        }

        // Fill in fields that can be used to construct path and filename
        final Map<String, String> fields = new HashMap<String, String>();
        fields.put("WORKERID", String.valueOf(workerId));
        fields.put("WORKERNAME", config.getProperty("NAME"));
        fields.put("REMOTEIP", (String) requestContext.get(RequestContext.REMOTE_IP));
        fields.put("TRANSACTIONID", (String) requestContext.get(RequestContext.TRANSACTION_ID));
        fields.put("REQUESTID", String.valueOf(sReq.getRequestID()));

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

        final File outputPath = new File(new File(config.getProperty(
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

        OutputStream out = null;
        try {
            out = new FileOutputStream(outputFile);
            out.write(signedbytes);
        } catch (IOException ex) {
            throw new SignServerException(
                    "Could not archive signed document", ex);
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException ex) {
                    LOG.debug("Exception closing file", ex);
                    throw new SignServerException(
                            "Could not archive signed document", ex);
                }
            }
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
                final SimpleDateFormat sdf = new SimpleDateFormat(
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

    private void checkForDuplicateObjects(byte[] pdfbytes) throws IOException,
            SignServerException {
        if (LOG.isDebugEnabled()) {
            LOG.debug(">checkForDuplicateObjects");
        }
        final PRTokeniser tokens = new PRTokeniser(pdfbytes);
        final Set<String> idents = new HashSet<String>();
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
        Object o = context.get(RequestContext.REQUEST_METADATA);
        if (o instanceof Map) {
            Map<String, String> metadata = (Map<String, String>) o;
            String password = metadata.get(RequestContext.METADATA_PDFPASSWORD);
            if (password == null) {
                result = null;
            } else {
                result = password.getBytes("ISO-8859-1");
}
        } else {
            result = null;
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

    protected TSAClient getTimeStampClient(String url, String username, String password) {
        return new TSAClientBouncyCastle(url, username, password);
    }

}
