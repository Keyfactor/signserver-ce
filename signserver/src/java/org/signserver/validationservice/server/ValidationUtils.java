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
import java.net.URL;
import java.net.URLConnection;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;

import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.signserver.common.SignServerException;

/**
 * 
 * utility functions used by validators 
 * @author rayback2
 *
 */
public class ValidationUtils {

	/**
	 * retrieve X509CRL from specified URL
	 * @param url
	 * @return
	 * @throws CertificateException
	 * @throws NoSuchProviderException
	 * @throws CRLException
	 * @throws IOException
	 * @throws SignServerException
	 */
	public static X509CRL fetchCRLFromURL(URL url) throws CertificateException, NoSuchProviderException, CRLException, IOException, SignServerException
	{
		CertificateFactory certFactory = CertificateFactory.getInstance("X509", "BC");
		return fetchCRLFromURL(url, certFactory);
	}
	
	/**
	 * retrieve X509CRL from specified URL, uses passed in CertificateFactory 
	 * @throws SignServerException 
	 */
	public static X509CRL fetchCRLFromURL(URL url, CertificateFactory certFactory) throws IOException, CRLException, SignServerException {
		URLConnection connection = url.openConnection();
		connection.setDoInput(true);
		connection.setUseCaches(false);

		byte[] responsearr = null;		
		InputStream reader = connection.getInputStream();
		int responselen = connection.getContentLength();
		
		if(responselen != -1) 
		{
						
			//header indicating content-length is present, so go ahead and use it
			responsearr = new byte[responselen];

			int offset = 0;
			int bread;
			while ((responselen > 0) && (bread = reader.read(responsearr, offset, responselen))!=-1) {
				offset += bread;
				responselen -= bread;
			}
			
			//read.read returned -1 but we expect inputstream to contain more data
			//is it a dreadful unexpected EOF we were afraid of ??
			if (responselen > 0) {
				throw new SignServerException("Unexpected EOF encountered while reading crl from : " + url.toString());
			}
		}
		else
		{
			//getContentLength() returns -1. no panic , perfect normal value if header indicating length is missing (javadoc)
			//try to read response manually byte by byte (small response expected , no need to buffer)
			ByteArrayOutputStream baos  = new ByteArrayOutputStream();
			int b;
			while ((b = reader.read())!=-1) {
				baos.write(b);
			}
			
			responsearr = baos.toByteArray();
		}

		ByteArrayInputStream bis = new ByteArrayInputStream(responsearr);
		X509CRL crl = (X509CRL)certFactory.generateCRL(bis);
		
		return crl;
	}

	public static int getReasonCodeFromCRLEntry(X509CRLEntry crlEntry) throws IOException
	{
		//retrieve reason
		byte[] reasonBytes = crlEntry.getExtensionValue(X509Extensions.ReasonCode.getId());
		if(reasonBytes == null)
		{
			//if null then unspecified (RFC 3280)
			return CRLReason.unspecified;
		}
		
		DEREnumerated reasonCode = (DEREnumerated)X509ExtensionUtil.fromExtensionValue(reasonBytes);
		
		return reasonCode.getValue().intValue();
	}
}
