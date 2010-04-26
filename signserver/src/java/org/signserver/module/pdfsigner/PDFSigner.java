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
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Vector;

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
import com.lowagie.text.pdf.OcspClientBouncyCastle;
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
import com.lowagie.text.pdf.TSAClient;
import com.lowagie.text.pdf.TSAClientBouncyCastle;

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
 * @author Tomas Gustavsson
 * @version $Id$
 */
public class PDFSigner extends BaseSigner {

	/** Log4j instance for actual implementation class */
	public transient Logger log = Logger.getLogger(this.getClass());
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

	public void init(int signerId, WorkerConfig config,
			WorkerContext workerContext, EntityManager workerEntityManager) {
		super.init(signerId, config, workerContext, workerEntityManager);
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

		// retrieve and preprocess configuration parameter values
		PDFSignerParameters params = new PDFSignerParameters(config);

		// Start processing the actual signature
		GenericSignResponse signResponse = null;
		byte[] pdfbytes = (byte[]) sReq.getRequestData();
		byte[] fpbytes = CertTools.generateSHA1Fingerprint(pdfbytes);
		String fp = new String(Hex.encode(fpbytes));
		if (requestContext.get(RequestContext.STATISTICS_EVENT) != null) {
			Event event = (Event) requestContext
					.get(RequestContext.STATISTICS_EVENT);
			event.addCustomStatistics("PDFBYTES", pdfbytes.length);
		}
		try {
			byte[] signedbytes = addSignatureToPDFDocument(params, pdfbytes);
			if (signRequest instanceof GenericServletRequest) {
				signResponse = new GenericServletResponse(sReq.getRequestID(),
						signedbytes, getSigningCertificate(), fp,
						new ArchiveData(signedbytes), "application/pdf");
			} else {
				signResponse = new GenericSignResponse(sReq.getRequestID(),
						signedbytes, getSigningCertificate(), fp,
						new ArchiveData(signedbytes));
			}
		} catch (DocumentException e) {
			log.error("Error signing PDF: ", e);
			throw new IllegalRequestException("DocumentException: "
					+ e.getMessage());
		} catch (IOException e) {
			log.error("Error signing PDF: ", e);
			throw new IllegalRequestException("IOException: " + e.getMessage());
		}

		return signResponse;
	}

	private byte[] addSignatureToPDFDocument(PDFSignerParameters params,
			byte[] pdfbytes) throws IOException, DocumentException,
			CryptoTokenOfflineException, SignServerException {

		// get signing cert certificate chain and private key
		Collection<Certificate> certs = this.getSigningCertificateChain();
		if (certs == null) {
			throw new IllegalArgumentException(
					"Null certificate chain. This signer needs a certificate.");
		}
		Certificate[] certChain = (Certificate[]) certs
				.toArray(new Certificate[0]);
		PrivateKey privKey = this.getCryptoToken().getPrivateKey(
				ICryptoToken.PURPOSE_SIGN);

		PdfReader reader = new PdfReader(pdfbytes);
		ByteArrayOutputStream fout = new ByteArrayOutputStream();
		PdfStamper stp = PdfStamper.createSignature(reader, fout, '\0', null,
				true);
		PdfSignatureAppearance sap = stp.getSignatureAppearance();

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
			sap.setVisibleSignature(new com.lowagie.text.Rectangle(params
					.getVisible_sig_rectangle_llx(), params
					.getVisible_sig_rectangle_lly(), params
					.getVisible_sig_rectangle_urx(), params
					.getVisible_sig_rectangle_ury()), signaturePage, null);

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
			tsc = new TSAClientBouncyCastle(params.getTsa_url(), params
					.getTsa_username(), params.getTsa_password());
		}

		int contentEstimated = 15000;
		HashMap exc = new HashMap();
		exc.put(PdfName.CONTENTS, new Integer(contentEstimated * 2 + 2));
		sap.preClose(exc);

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

		InputStream data = sap.getRangeStream();
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance("SHA1");
		} catch (NoSuchAlgorithmException e) {
			throw new SignServerException("Error creating SHA1 digest", e);
		}
		byte buf[] = new byte[8192];
		int n;
		while ((n = data.read(buf)) > 0) {
			messageDigest.update(buf, 0, n);
		}
		byte hash[] = messageDigest.digest();
		Calendar cal = Calendar.getInstance();

		// embed ocsp response in cms package if requested
		// for ocsp request to be formed there needs to be issuer certificate in
		// chain
		byte[] ocsp = null;
		if (params.isEmbed_ocsp_response() && certChain.length >= 2) {
			String url;
			try {
				url = PdfPKCS7.getOCSPURL((X509Certificate) certChain[0]);
				if (url != null && url.length() > 0)
					ocsp = new OcspClientBouncyCastle(
							(X509Certificate) certChain[0],
							(X509Certificate) certChain[1], url).getEncoded();
			} catch (CertificateParsingException e) {
				throw new SignServerException(
						"Error getting OCSP URL from certificate", e);
			}

		}

		byte sh[] = sgn.getAuthenticatedAttributeBytes(hash, cal, ocsp);
		try {
			sgn.update(sh, 0, sh.length);
		} catch (SignatureException e) {
			throw new SignServerException("Error calculating signature", e);
		}

		byte[] encodedSig = sgn.getEncodedPKCS7(hash, cal, tsc, ocsp);

		if (contentEstimated + 2 < encodedSig.length)
			throw new SignServerException("Not enough space");

		byte[] paddedSig = new byte[contentEstimated];
		System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);

		PdfDictionary dic2 = new PdfDictionary();
		dic2
				.put(PdfName.CONTENTS, new PdfString(paddedSig)
						.setHexWriting(true));
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
	private CRL[] getCrlsForChain(Collection<Certificate> pCertChain)
			throws SignServerException {

		List<CRL> retCrls = new Vector<CRL>();
		for (Certificate currCert : pCertChain) {
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

		if (retCrls.size() == 0) {
			return null;
		} else {
			return retCrls.toArray(new CRL[0]);
		}

	}

        static URL getCRLDistributionPoint(final Certificate certificate)
                throws CertificateParsingException {
            return org.signserver.module.pdfsigner.org.ejbca.util
                    .CertTools.getCrlDistributionPoint(certificate);
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
		if (pParams.getVisible_sig_page().trim().equals("First"))
			return 1;
		else if (pParams.getVisible_sig_page().trim().equals("Last"))
			return totalNumOfPages;
		else {
			try {
				int pNum = Integer.parseInt(pParams.getVisible_sig_page());
				if (pNum < 1)
					return 1;
				else if (pNum > totalNumOfPages)
					return totalNumOfPages;
				else
					return pNum;
			} catch (NumberFormatException ex) {
				// not a numeric argument draw on first line
				return 1;
			}
		}
	}
}
