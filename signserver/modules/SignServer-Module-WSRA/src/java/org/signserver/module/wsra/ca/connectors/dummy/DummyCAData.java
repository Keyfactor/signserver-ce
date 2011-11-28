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
 
package org.signserver.module.wsra.ca.connectors.dummy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Externalizable;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.module.wsra.ca.ICertRequestData;
import org.signserver.module.wsra.ca.connectors.AlreadyRevokedException;
import org.signserver.module.wsra.common.WSRAConstants;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.Validation.Status;

/**
 * A Dummy CA implementation that represent one issuer in
 * a DummyCA connection. It stores all data on file (unencrypted)
 * in USER_HOME/dummyca_<issuercn>.data
 * 
 * 
 * @author Philip Vendil 19 okt 2008
 *
 * @version $Id$
 */

public class DummyCAData implements Externalizable {
	

	private static final long serialVersionUID = 1L;

	private static final int VERSION = 1;
	
	private transient Logger log = Logger.getLogger(this.getClass());
	
	public static final long DEFAULT_VALIDITY = 3650L; // 10 years.
	public static final String DEFAULT_SIGNALG = "SHA1WithRSA"; // 10 years.

	private X509Certificate cACert;	
	private PrivateKey cAKey;
	private String issuerDN;
	
	private HashMap<ICertificate,Validation> certsAndValidations;
	
	public DummyCAData(String issuerDN, Properties props){
		this.issuerDN = issuerDN;
		try {
			KeyPair cAKeys = KeyTools.genKeys("2048", "RSA");
			cAKey = cAKeys.getPrivate();
			
			Date firstDate = new Date();
			firstDate.setTime(firstDate.getTime() - (10 * 60 * 1000));
			Date lastDate = new Date();
			lastDate.setTime(lastDate.getTime() + (DEFAULT_VALIDITY * (24 * 60 * 60 * 1000)));
			X509V3CertificateGenerator certgen = new X509V3CertificateGenerator();

			// Serialnumber is random bits, where random generator is initialized with Date.getTime() when this
			// bean is created.
			byte[] serno = new byte[8];
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			random.setSeed((new Date().getTime()));
			random.nextBytes(serno);
			certgen.setSerialNumber((new java.math.BigInteger(serno)).abs());
			certgen.setNotBefore(firstDate);
			certgen.setNotAfter(lastDate);
			certgen.setSignatureAlgorithm(DEFAULT_SIGNALG);
			certgen.setSubjectDN(CertTools.stringToBcX509Name(issuerDN));
			certgen.setIssuerDN(CertTools.stringToBcX509Name(issuerDN));
			certgen.setPublicKey(cAKeys.getPublic());

			// Basic constranits is always critical and MUST be present at-least in CA-certificates.
			BasicConstraints bc = new BasicConstraints(true);
			certgen.addExtension(X509Extensions.BasicConstraints.getId(), true, bc);

			int keyusage = X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
			X509KeyUsage ku = new X509KeyUsage(keyusage);
			certgen.addExtension(X509Extensions.KeyUsage.getId(), true, ku);


			// Subject and Authority key identifier is always non-critical and MUST be present for certificates to verify in Mozilla.
			try {            
				SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(
						new ByteArrayInputStream(cAKeys.getPublic().getEncoded())).readObject());
				SubjectKeyIdentifier ski = new SubjectKeyIdentifier(spki);

				SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(
						new ByteArrayInputStream(cAKeys.getPublic().getEncoded())).readObject());
				AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);

				certgen.addExtension(X509Extensions.SubjectKeyIdentifier.getId(), false, ski);
				certgen.addExtension(X509Extensions.AuthorityKeyIdentifier.getId(), false, aki);            
			} catch (IOException e) { // do nothing
			}
			cACert =  certgen.generate(cAKey);
			
			// Add validation
			certsAndValidations = new HashMap<ICertificate, Validation>();
			Validation v = new Validation(org.signserver.validationservice.common.X509Certificate.getInstance(cACert),
					                      getCACertificateChain(),
					                      Validation.Status.VALID,""
					                      );
			certsAndValidations.put(org.signserver.validationservice.common.X509Certificate.getInstance(cACert), v);
			
			storeData();
		} catch (Exception e) {
			log.error("Error generating dummy CA certificate.",e);
		}        
	}
	
	/**
	 * Constructor used when serializing
	 * 
	 */
	public DummyCAData(){}
	


	public List<ICertificate> getCACertificateChain()
			throws SignServerException {
		ArrayList<ICertificate> retval = new ArrayList<ICertificate>();
		try {
			retval.add(org.signserver.validationservice.common.X509Certificate.getInstance(cACert));
		} catch (Exception e) {
			throw new SignServerException(e.getMessage(),e);
		}
		return retval;
	}


	public Validation getCertificateStatus(
			ICertificate certificate) {
		return certsAndValidations.get(certificate);
	}


	public ICertificate requestCertificate(ICertRequestData certReqData) throws IllegalRequestException,
			SignServerException {
		try{
			Date firstDate = new Date();
			firstDate.setTime(firstDate.getTime() - (10 * 60 * 1000));
			Date lastDate = new Date();
			long untilTime =  1000L * 3600L * 24L *3651L;
			lastDate.setTime(System.currentTimeMillis() + untilTime);			
			X509V3CertificateGenerator certgen = new X509V3CertificateGenerator();

			// Serialnumber is random bits, where random generator is initialized with Date.getTime() when this
			// bean is created.
			byte[] serno = new byte[8];
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			random.setSeed((new Date().getTime()));
			random.nextBytes(serno);
			certgen.setSerialNumber((new java.math.BigInteger(serno)).abs());
			certgen.setNotBefore(firstDate);
			certgen.setNotAfter(lastDate);
			certgen.setSignatureAlgorithm(DEFAULT_SIGNALG);
			certgen.setSubjectDN(CertTools.stringToBcX509Name(certReqData.getSubjectDN()));
			certgen.setIssuerDN(CertTools.stringToBcX509Name(issuerDN));
			certgen.setPublicKey(certReqData.getPublicKey());

			BasicConstraints bc = new BasicConstraints(false);
			certgen.addExtension(X509Extensions.BasicConstraints.getId(), true, bc);

			int keyusage = X509KeyUsage.keyEncipherment + X509KeyUsage.digitalSignature;
			X509KeyUsage ku = new X509KeyUsage(keyusage);
			certgen.addExtension(X509Extensions.KeyUsage.getId(), true, ku);

			Vector<DERObjectIdentifier> extendedKeyUsage = new Vector<DERObjectIdentifier>();
			extendedKeyUsage.add(new DERObjectIdentifier("1.3.6.1.5.5.7.3.1")); //SERVERAUTH
			extendedKeyUsage.add(new DERObjectIdentifier("1.3.6.1.5.5.7.3.2")); //CLIENTAUTH
			extendedKeyUsage.add(new DERObjectIdentifier("1.3.6.1.5.5.7.3.4")); //EMAILPROTECTION
			extendedKeyUsage.add(new DERObjectIdentifier("1.3.6.1.4.1.311.20.2.2")); // SMARTCARDLOGON

			ExtendedKeyUsage eku = new ExtendedKeyUsage(extendedKeyUsage);
			// Extended Key Usage may be either critical or non-critical
			certgen.addExtension(
					X509Extensions.ExtendedKeyUsage.getId(),
					false,
					eku);            	


			if(certReqData.getSubjectAltName() != null){
				GeneralNames san = CertTools.getGeneralNamesFromAltName(certReqData.getSubjectAltName());            
				if (san != null) {
					certgen.addExtension(X509Extensions.SubjectAlternativeName.getId(), false, san);
				}
			}


			// Subject and Authority key identifier is always non-critical and MUST be present for certificates to verify in Mozilla.
			try {            
				SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(
						new ByteArrayInputStream(certReqData.getPublicKey().getEncoded())).readObject());
				SubjectKeyIdentifier ski = new SubjectKeyIdentifier(spki);

				SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(
						new ByteArrayInputStream(cACert.getPublicKey().getEncoded())).readObject());
				AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);

				certgen.addExtension(X509Extensions.SubjectKeyIdentifier.getId(), false, ski);
				certgen.addExtension(X509Extensions.AuthorityKeyIdentifier.getId(), false, aki);            
			} catch (IOException e) { // do nothing
			}
			org.signserver.validationservice.common.X509Certificate cert =  org.signserver.validationservice.common.X509Certificate.getInstance(certgen.generate(cAKey));
			Validation v = new Validation(cert,
					getCACertificateChain(),
					Validation.Status.VALID,""
			);
			certsAndValidations.put(cert,v);

			storeData();
			
			return cert;
		}catch(IOException e){
            log.error("Error generating dummy certificate : "+ e.getMessage(),e);
            throw new SignServerException(e.getMessage(),e);
		} catch (CertificateEncodingException e) {
			log.error("Error generating dummy certificate : "+ e.getMessage(),e);
            throw new SignServerException(e.getMessage(),e);
		} catch (CertificateParsingException e) {
			log.error("Error generating dummy certificate : "+ e.getMessage(),e);
            throw new SignServerException(e.getMessage(),e);
		} catch (InvalidKeyException e) {
			log.error("Error generating dummy certificate : "+ e.getMessage(),e);
            throw new SignServerException(e.getMessage(),e);
		} catch (IllegalStateException e) {
			log.error("Error generating dummy certificate : "+ e.getMessage(),e);
            throw new SignServerException(e.getMessage(),e);
		} catch (NoSuchAlgorithmException e) {
			log.error("Error generating dummy certificate : "+ e.getMessage(),e);
            throw new SignServerException(e.getMessage(),e);
		} catch (SignatureException e) {
			log.error("Error generating dummy certificate : "+ e.getMessage(),e);
            throw new SignServerException(e.getMessage(),e);
		}		
	}

	public void revokeCertificate(ICertificate cert, int reason)
			throws IllegalRequestException, AlreadyRevokedException, SignServerException {
		if(certsAndValidations.get(cert) == null){
			throw new IllegalRequestException("Error, this dummy CA haven't issued the given certificate " + cert.toString());
		}
		
		Validation v = certsAndValidations.get(cert);
		
		// Handle unrevoke
		if(reason == WSRAConstants.REVOKATION_REASON_NOT_REVOKED){
			if(v.getRevokationReason() == WSRAConstants.REVOKATION_REASON_NOT_REVOKED
			  || v.getRevokationReason() == WSRAConstants.REVOKATION_REASON_CERTIFICATEHOLD){
				Status status = v.getStatus();
				String statusMessage = v.getStatusMessage();
				if(status.equals(Status.REVOKED)){
					status = Status.VALID;
					statusMessage = "";
				}
				
               v = new Validation(v.getCertificate(),v.getCAChain(),status, statusMessage);				
			}else{
				throw new IllegalRequestException("Error, not possible to unrevoke certificate with revoke reason : " +v.getRevokationReason());
			}
		}else{
			if(v.getRevokationReason() == WSRAConstants.REVOKATION_REASON_NOT_REVOKED
			 || v.getRevokationReason() == WSRAConstants.REVOKATION_REASON_CERTIFICATEHOLD){
				Status status = Status.REVOKED;
				String statusMessage = "Certificate is revoked";
				v = new Validation(v.getCertificate(),v.getCAChain(),status, statusMessage,new Date(),reason);
			}else{
				throw new AlreadyRevokedException("Error, not possible to revoke an already permanently revoked certificate ");
			}
		}
		
		certsAndValidations.put(cert, v);
		
		try {
			storeData();
		} catch (IOException e) {
			throw new SignServerException("Error storing dummy CA data",e);
		}
	}
	


	public void readExternal(ObjectInput in) throws IOException,
			ClassNotFoundException {
		try{
			@SuppressWarnings("unused")
			int version = in.readInt();	
			
			int dataLen = in.readInt();
			byte data[] = new byte[dataLen];
			in.readFully(data);
			
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new ByteArrayInputStream(data), "foo123".toCharArray());
			cAKey = (PrivateKey) ks.getKey("CA", "foo123".toCharArray());
			cACert = (X509Certificate) ks.getCertificate("CA");
						
			dataLen = in.readInt();
			data = new byte[dataLen];
			in.readFully(data);
			issuerDN = new String(data,"UTF-8");
								
            int validationSize = in.readInt();
            certsAndValidations = new HashMap<ICertificate, Validation>();
            for(int i=0;i<validationSize;i++){
            	Validation v = new Validation();
            	v.parse(in);
            	certsAndValidations.put(v.getCertificate(), v);
            }
			
		} catch (CertificateEncodingException e) {
			log.error(e);
			throw new IOException(e);
		} catch (CertificateException e) {
			log.error(e);
			throw new IOException(e);
		} catch (NoSuchAlgorithmException e) {
			log.error(e);
			throw new IOException(e);
		}  catch (KeyStoreException e) {
			log.error(e);
			throw new IOException(e);
		} catch (UnrecoverableKeyException e) {
			log.error(e);
			throw new IOException(e);
		} 
	}

	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(VERSION);
		
		try {

			KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(null, "foo123".toCharArray());
			ks.setKeyEntry("CA", cAKey, "foo123".toCharArray(),new Certificate[] {cACert});
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ks.store(baos, "foo123".toCharArray());
			byte[]  data = baos.toByteArray();
			out.writeInt(data.length);
			out.write(data,0,data.length);	
	        
			data = issuerDN.getBytes("UTF-8");
			out.writeInt(data.length);
			out.write(data);					
			
			out.writeInt(certsAndValidations.size());		
			for(Validation v : certsAndValidations.values()){
				v.serialize(out);
			}			
		} catch (CertificateEncodingException e) {
			log.error(e);
			throw new IOException(e);
		} catch (KeyStoreException e) {
			log.error(e);
			throw new IOException(e);
		} catch (NoSuchAlgorithmException e) {
			log.error(e);
			throw new IOException(e);
		} catch (CertificateException e) {
			log.error(e);
			throw new IOException(e);
		}
	}
	
	public static String getStoreFileName(String issuerDN){
		String strippedDN = CertTools.getPartFromDN(issuerDN,"cn").replaceAll(" ", "").toLowerCase();
		
		return System.getProperty("user.home") + System.getProperty("file.separator") + "dummyca_" + strippedDN + ".data";
	}
	
	private void storeData() throws IOException {
		FileOutputStream fos = new FileOutputStream(DummyCAData.getStoreFileName(issuerDN));
		ObjectOutputStream oos = new ObjectOutputStream(fos);
		oos.writeObject(this);
		oos.close();
	}

}
