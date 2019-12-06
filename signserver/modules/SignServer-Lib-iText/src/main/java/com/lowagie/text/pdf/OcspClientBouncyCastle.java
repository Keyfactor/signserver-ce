/*
 * $Id: OcspClientBouncyCastle.java 3959 2009-06-09 08:31:05Z blowagie $
 *
 * Copyright 2009 Paulo Soares
 *
 * The contents of this file are subject to the Mozilla Public License Version 1.1
 * (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the License.
 *
 * The Original Code is 'iText, a free JAVA-PDF library'.
 *
 * The Initial Developer of the Original Code is Bruno Lowagie. Portions created by
 * the Initial Developer are Copyright (C) 1999-2005 by Bruno Lowagie.
 * All Rights Reserved.
 * Co-Developer of the code is Paulo Soares. Portions created by the Co-Developer
 * are Copyright (C) 2009 by Paulo Soares. All Rights Reserved.
 *
 * Contributor(s): all the names of the contributors are added in the source code
 * where applicable.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * LGPL license (the "GNU LIBRARY GENERAL PUBLIC LICENSE"), in which case the
 * provisions of LGPL are applicable instead of those above.  If you wish to
 * allow use of your version of this file only under the terms of the LGPL
 * License and not to allow others to use your version of this file under
 * the MPL, indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the LGPL.
 * If you do not delete the provisions above, a recipient may use your version
 * of this file under either the MPL or the GNU LIBRARY GENERAL PUBLIC LICENSE.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MPL as stated above or under the terms of the GNU
 * Library General Public License as published by the Free Software Foundation;
 * either version 2 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Library general Public License for more
 * details.
 *
 * If you didn't download this code from the following link, you should check if
 * you aren't using an obsolete version:
 * http://www.lowagie.com/iText/
 */

package com.lowagie.text.pdf;

import com.lowagie.text.ExceptionConverter;
import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * OcspClient implementation using BouncyCastle.
 * @author psoares
 * @since	2.1.6
 */
public class OcspClientBouncyCastle implements OcspClient {
    /** root certificate */
    private X509Certificate rootCert;
    /** check certificate */
    private X509Certificate checkCert;
    /** OCSP URL */
    private String url;
    
    /**
     * Creates an instance of an OcspClient that will be using BouncyCastle.
     * @param checkCert	the check certificate
     * @param rootCert	the root certificate
     * @param url	the OCSP URL
     */
    public OcspClientBouncyCastle(X509Certificate checkCert, X509Certificate rootCert, String url) {
        this.checkCert = checkCert;
        this.rootCert = rootCert;
        this.url = url;
    }
    
    /**
     * Generates an OCSP request using BouncyCastle.
     * @param issuerCert	certificate of the issues
     * @param serialNumber	serial number
     * @return	an OCSP request
     * @throws OCSPException
     * @throws IOException
     */
    private static OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws OCSPException, IOException, CertificateEncodingException, OperatorCreationException {
        //Add provider BC
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        
        // Generate the id for the certificate we are looking for
        CertificateID id = new JcaCertificateID(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1), issuerCert, serialNumber);
        
        // basic request generation with nonce
        OCSPReqBuilder gen = new OCSPReqBuilder();
        
        gen.addRequest(id);
        
        // create details for nonce extension
        gen.setRequestExtensions(new Extensions(new Extension[] { new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(new DEROctetString(PdfEncryption.createDocumentId()).getEncoded())) }));
        
        return gen.build();
    }
    
    /**
     * @return 	a byte array
     * @see com.lowagie.text.pdf.OcspClient#getEncoded()
     */
    public byte[] getEncoded() {
        try {
            OCSPReq request = generateOCSPRequest(rootCert, checkCert.getSerialNumber());
            byte[] array = request.getEncoded();
            URL urlt = new URL(url);
            HttpURLConnection con = (HttpURLConnection)urlt.openConnection();
            con.setRequestProperty("Content-Type", "application/ocsp-request");
            con.setRequestProperty("Accept", "application/ocsp-response");
            con.setDoOutput(true);
            OutputStream out = con.getOutputStream();
            DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
            dataOut.write(array);
            dataOut.flush();
            dataOut.close();
            if (con.getResponseCode() / 100 != 2) {
                throw new IOException("Invalid HTTP response");
            }
            //Get Response
            InputStream in = (InputStream) con.getContent();
            OCSPResp ocspResponse = new OCSPResp(OCSPResponse.getInstance(new ASN1InputStream(in).readObject()));

            if (ocspResponse.getStatus() != 0)
                throw new IOException("Invalid status: " + ocspResponse.getStatus());
            BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
            if (basicResponse != null) {
                SingleResp[] responses = basicResponse.getResponses();
                if (responses.length == 1) {
                    SingleResp resp = responses[0];
                    Object status = resp.getCertStatus();
                    if (status == CertificateStatus.GOOD) {
                        return basicResponse.getEncoded();
                    }
                    else if (status instanceof RevokedStatus) {
                        throw new IOException("OCSP Status is revoked!");
                    }
                    else {
                        throw new IOException("OCSP Status is unknown!");
                    }
                }
            }
        }
        catch (Exception ex) {
            throw new ExceptionConverter(ex);
        }
        return null;
    }
}
