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
package org.signserver.validationservice.server;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.*;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.jcajce.JcaRespID;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.signserver.common.SignServerException;

/**
 * Utility functions used by validators.
 *
 * @author rayback2
 * @version $Id$
 */
public class ValidationUtils {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ValidationUtils.class);

    /**
     * retrieve X509CRL from specified URL
     * 
     * @param url
     * @return the downloaded CRL
     * @throws SignServerException
     */
    public static X509CRL fetchCRLFromURL(URL url) throws SignServerException {

        CertificateFactory certFactory = null;
        try {
            certFactory = CertificateFactory.getInstance("X509", "BC");
        } catch (CertificateException e) {
            throw new SignServerException(
                    "Error creating BC CertificateFactory provider", e);
        } catch (NoSuchProviderException e) {
            throw new SignServerException(
                    "Error creating BC CertificateFactory provider", e);
        }
        return fetchCRLFromURLwithRetry(url, certFactory, 3, 100);
    }

    private static X509CRL fetchCRLFromURLwithRetry(URL url, CertificateFactory certFactory, int retries, long waitTime) throws SignServerException {
        X509CRL result = null;
        SignServerException lastException = null;
        for (int i = 0; i < retries && result == null; i++) {
            try {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Fetching CRL from: " + url);
                }
                result = fetchCRLFromURL(url, certFactory);
            } catch (SignServerException ex) {
                lastException = ex;
                LOG.info("CRL fetch (" + (i + 1) + " of " + retries + ")" + " failed: " + ex.getMessage());
                try {
                    Thread.sleep(waitTime);
                } catch (InterruptedException ignored) {
                    break;
                }
            }
        }
        if (result == null && lastException != null) {
            throw lastException;
        }
        return result;
    }

    /**
     * retrieve X509CRL from specified URL, uses passed in CertificateFactory
     * 
     * @throws SignServerException
     */
    public static X509CRL fetchCRLFromURL(URL url,
            CertificateFactory certFactory) throws SignServerException {
        URLConnection connection;
        try {
                connection = url.openConnection();
            } catch (IOException e) {
                throw new SignServerException(
                        "Error opening connection for fetching CRL from address : "
                        + url.toString(), e);
            }
            connection.setDoInput(true);

            byte[] responsearr = null;
            InputStream reader = null;
            try {
                try {
                    reader = connection.getInputStream();
                } catch (IOException e) {
                    throw new SignServerException(
                            "Error getting input stream for fetching CRL from address : "
                            + url.toString(), e);
                }
                int responselen = connection.getContentLength();

                if (responselen != -1) {

                    // header indicating content-length is present, so go ahead and use
                    // it
                    responsearr = new byte[responselen];

                    int offset = 0;
                    int bread;
                    try {
                        while ((responselen > 0)
                                && (bread = reader.read(responsearr, offset,
                                responselen)) != -1) {
                            offset += bread;
                            responselen -= bread;
                        }
                    } catch (IOException e) {
                        throw new SignServerException(
                                "Error reading CRL bytes from address : "
                                + url.toString(), e);
                    }

                    // read.read returned -1 but we expect inputstream to contain more
                    // data
                    // is it a dreadful unexpected EOF we were afraid of ??
                    if (responselen > 0) {
                        throw new SignServerException(
                                "Unexpected EOF encountered while reading crl from : "
                                + url.toString());
                    }
                } else {
                    // getContentLength() returns -1. no panic , perfect normal value if
                    // header indicating length is missing (javadoc)
                    // try to read response manually byte by byte (small response
                    // expected , no need to buffer)
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    int b;
                    try {
                        while ((b = reader.read()) != -1) {
                            baos.write(b);
                        }
                    } catch (IOException e) {
                        throw new SignServerException(
                                "Error reading input stream for fetching CRL from address (no length header): "
                                + url.toString(), e);
                    }

                    responsearr = baos.toByteArray();
                }
            } finally {
                if (reader != null) {
                    try {
                        reader.close();
                    } catch (IOException ex) {
                        LOG.info("Could not close stream after reading CRL", ex);
                    }
                }
            }
        
            ByteArrayInputStream bis = new ByteArrayInputStream(responsearr);
            X509CRL crl;
            try {
                crl = (X509CRL) certFactory.generateCRL(bis);
            } catch (CRLException e) {
                throw new SignServerException(
                        "Error creating CRL object with bytes from address : "
                        + url.toString(), e);
            }
  
        return crl;
    }

    public static int getReasonCodeFromCRLEntry(X509CRLEntry crlEntry)
            throws IOException {
        // retrieve reason
        byte[] reasonBytes = crlEntry.getExtensionValue(X509Extension.reasonCode.getId());
        if (reasonBytes == null) {
            // if null then unspecified (RFC 3280)
            return CRLReason.unspecified;
        }

        DEREnumerated reasonCode = (DEREnumerated) X509ExtensionUtil.fromExtensionValue(reasonBytes);

        return reasonCode.getValue().intValue();
    }
    
    /**
     * Sends a request to the OCSP responder and returns the results.
     *
     * Note: Based on code from the EJBCA ValidationTool.
     *
     * @param url of the OCSP responder
     * @param request to send
     * @return An OCSPResponse object filled with information about the response
     * @throws IOException in case of networking related errors
     * @throws OCSPException in case of error parsing the response
     */
    public static OCSPResponse queryOCSPResponder(URL url, OCSPReq request) throws IOException, OCSPException {
        final OCSPResponse result = new OCSPResponse();
        
        final HttpURLConnection con;
        final URLConnection urlCon = url.openConnection();
        if (!(urlCon instanceof HttpURLConnection)) {
            throw new IOException("Unsupported protocol in URL: " + url);
        }
        con = (HttpURLConnection) urlCon;

        // POST the OCSP request
        con.setDoOutput(true);
        con.setRequestMethod("POST");

        // POST it
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        OutputStream os = null;
        try {
            os = con.getOutputStream();
            os.write(request.getEncoded());
        } finally {
            if (os != null) {
                os.close();
            }
        }

        result.setHttpReturnCode(con.getResponseCode());
        if (result.getHttpReturnCode() != 200) {
            if (result.getHttpReturnCode() == 401) {
                result.setError(OCSPResponse.Error.httpUnauthorized);
            } else {
                result.setError(OCSPResponse.Error.unknown);
            }
            return result;
        }

        OCSPResp response = null;
        InputStream in = null;
        try {
            in = con.getInputStream();
            if (in != null) {
                ByteArrayOutputStream bout = new ByteArrayOutputStream();
                int b;
                while ( (b = in.read()) != -1) {
                    bout.write(b);
                }
                response = new OCSPResp(bout.toByteArray());
            }
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }

        if (response == null) {
            result.setError(OCSPResponse.Error.noResponse);
            return result;
        }
        result.setResp(response);

        if (response.getStatus() != OCSPResponseStatus.SUCCESSFUL) {
            result.setError(OCSPResponse.Error.fromBCOCSPResponseStatus(response.getStatus()));
            return result;
        }

        final BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
        result.setResponseObject(brep);
        if ( brep==null ) {
            result.setError(OCSPResponse.Error.noResponse);
            return result;
        }

        final RespID id = brep.getResponderId();
        final DERTaggedObject to = (DERTaggedObject)id.toASN1Object().toASN1Object();
        final RespID respId;

        final X509CertificateHolder[] chain = brep.getCerts();
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        X509Certificate signerCertificate;
        try {
            signerCertificate = converter.getCertificate(chain[0]);
        } catch (CertificateException ex) {
            throw new IOException("Could not convert certificate: " + ex.getMessage());
        }
        result.setSignerCertificate(signerCertificate);

        if (to.getTagNo() == 1) {
            // This is Name
            respId = new JcaRespID(signerCertificate.getSubjectX500Principal());
        } else {
            // This is KeyHash
            final PublicKey signerPub = signerCertificate.getPublicKey();
            try {
                respId = new JcaRespID(signerPub, new JcaDigestCalculatorProviderBuilder().build().get(RespID.HASH_SHA1));
            } catch (OperatorCreationException ex) {
                throw new IOException("Could not create respId: " + ex.getMessage());
            }
        }
        if (!id.equals(respId)) {
            // Response responderId does not match signer certificate responderId!
            result.setError(OCSPResponse.Error.invalidSignerId);
        }

        result.setIssuerDN(signerCertificate.getIssuerX500Principal());

        return result;
    }
}