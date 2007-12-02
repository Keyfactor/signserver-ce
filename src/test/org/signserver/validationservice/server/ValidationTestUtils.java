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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

/**
 * Contains help methods for testing the validation service
 * 
 * 
 * @author Philip Vendil 30 nov 2007
 *
 * @version $Id: ValidationTestUtils.java,v 1.1 2007-12-02 20:34:42 herrvendil Exp $
 */

public class ValidationTestUtils {
	
	public static X509Certificate genCert(String dn, String issuerdn, PrivateKey privKey, PublicKey pubKey, Date startDate, Date endDate, boolean isCA) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, SignatureException{
		return genCert(dn, issuerdn, privKey, pubKey, startDate, endDate, isCA,0);
	}
	
	public static X509Certificate genCert(String dn, String issuerdn, PrivateKey privKey, PublicKey pubKey, Date startDate, Date endDate, boolean isCA,int keyUsage) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, SignatureException{
	        X509V3CertificateGenerator certgen = new X509V3CertificateGenerator();

	        byte[] serno = new byte[8];
	        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
	        random.setSeed((new Date().getTime()));
	        random.nextBytes(serno);
	        certgen.setSerialNumber((new java.math.BigInteger(serno)).abs());
	        certgen.setNotBefore(startDate);
	        certgen.setNotAfter(endDate);
	        certgen.setSignatureAlgorithm("SHA1WithRSA");
	        certgen.setSubjectDN(CertTools.stringToBcX509Name(dn));
	        certgen.setIssuerDN(CertTools.stringToBcX509Name(issuerdn));
	        certgen.setPublicKey(pubKey);

	        // Basic constranits is always critical and MUST be present at-least in CA-certificates.
	        BasicConstraints bc = new BasicConstraints(isCA);
	        certgen.addExtension(X509Extensions.BasicConstraints.getId(), true, bc);

	        // Put critical KeyUsage in CA-certificates
	        if(keyUsage == 0){
	        	if (isCA == true) {
	        		int keyusage = X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
	        		X509KeyUsage ku = new X509KeyUsage(keyusage);
	        		certgen.addExtension(X509Extensions.KeyUsage.getId(), true, ku);
	        	}
	        }else{
	        	X509KeyUsage ku = new X509KeyUsage(keyUsage);
        		certgen.addExtension(X509Extensions.KeyUsage.getId(), true, ku);
	        }
	        X509Certificate cert = certgen.generate(privKey);

	        return cert;
	}
	
	public static String genPEMStringFromChain(List<X509Certificate> chain) throws CertificateEncodingException{
        String beginKey = "\n-----BEGIN CERTIFICATE-----\n";
        String endKey = "\n-----END CERTIFICATE-----\n";
        String retval = "";
        for(X509Certificate cert : chain){
          retval +=	beginKey ;
          retval +=  new String(Base64.encode(cert.getEncoded(), true));
          retval += endKey ;
        }
		
		return retval;
	}

}
