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

package org.signserver.cli.genservercert;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;




/**
 * A small cli program not included in the rest of the CLI
 * and is built into it's own jar. It
 * generates a tomcat.jks, a CA certificate, a
 * truststore.jks and a testclient.jks from the given 
 * issuerDN and subjectDN parameters.
 * 
 * 
 * @author Philip Vendil 12 maj 2008
 *
 * @version $Id$
 */

public class GenServerCertificate {

	private static final int ISSUERDN          = 0;
	private static final int SUBJECTDN         = 1;
	private static final int OUTPATH           = 2;
	private static final int TOMCAT_PASSWD     = 3;
	private static final int TRUSTSTORE_PASSWD = 4;
	private static final int TESTCLIENT_PASSWD = 5;
	

	
	public GenServerCertificate() {	}

	/**
	 * Main program 
	 * @param args (
	 */
	public static void main(String[] args) {
		if(args.length < 6){
			displayUsageAndExit();
			
		}
		installBCProvider();
		
		String issuerDN = args[ISSUERDN];
		X509Name issuerName = new X509Name(issuerDN);		
		if(issuerName == null){
			System.out.println("Error: Illegal Issuer DN : " + issuerDN);
			displayUsageAndExit();
		}
		String subjectDN = args[SUBJECTDN];
		X509Name subjectName = new X509Name(subjectDN);		
		if(subjectName == null ){
			System.out.println("Error: Illegal Subject DN : " + subjectDN);
			displayUsageAndExit();
		}
		
		String outPath = args[OUTPATH]; 
		File outPathDir = new File(outPath);
		if(!outPathDir.exists() || !outPathDir.isDirectory() || !outPathDir.canWrite()){
			System.out.println("Error: Illegal out path : " + outPath + ", check that the directory exists, is a directory and that the user have write access.");
			displayUsageAndExit();
		}
		
		String tomcatPasswd = args[TOMCAT_PASSWD];
		String truststorePasswd = args[TRUSTSTORE_PASSWD];
		String testClientPasswd = args[TESTCLIENT_PASSWD];
		
		GenServerCertificate main = new GenServerCertificate();
		try{
			main.run(issuerName,subjectName,outPath,tomcatPasswd,truststorePasswd,testClientPasswd);	
		}catch(Exception e){
			System.out.println("Error generating server certificate : " + e.getMessage());
			e.printStackTrace();
			System.exit(-1);
		}
        System.exit(0);
		
	}

	public static void installBCProvider(){
		if (Security.addProvider(new BouncyCastleProvider()) < 0) {         
			Security.removeProvider("BC");
			if (Security.addProvider(new BouncyCastleProvider()) < 0) {
				System.out.println("Cannot even install BC provider again!");
			} 

		}
	}
	
	private void run(X509Name issuerDN,
			         X509Name subjectDN, 
                     String outPath,
                     String tomcatPasswd,
                     String truststorePasswd,
                     String testClientPasswd) throws Exception {
		System.out.println("  Generating CA Certificate...");
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
		keygen.initialize(2048);
		KeyPair cAKeys = keygen.generateKeyPair();		
		X509Certificate caCert = genCert(issuerDN, issuerDN, 3650, cAKeys.getPrivate(), cAKeys.getPublic(), true, X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign,null);
		X509Certificate[] cacerts = new X509Certificate[1];
		cacerts[0] = caCert;
		writeCACertToPEM(caCert,outPath);
		System.out.println("  CA Certificate Generated Successfully.");
		System.out.println("  Generating SSL Server (tomcat.jks) Keystore...");		
		KeyPair sSLServerKeys = keygen.generateKeyPair();		
	    ArrayList<String> sSLServerEKU = new ArrayList<String>();
	    sSLServerEKU.add("1.3.6.1.5.5.7.3.1");	    
		X509Certificate sSLServerCert = genCert(issuerDN, subjectDN, 3650, cAKeys.getPrivate(), sSLServerKeys.getPublic(), false, X509KeyUsage.digitalSignature + X509KeyUsage.keyEncipherment,sSLServerEKU);
		KeyStore tomcat = createUserJKS("tomcat", sSLServerKeys.getPrivate(), tomcatPasswd, sSLServerCert, cacerts);
		FileOutputStream fos = new FileOutputStream(outPath+ File.separator + "tomcat.jks");
		tomcat.store(fos, tomcatPasswd.toCharArray());
		fos.close();
		System.out.println("  SSL Server Keystore Generated Successfully.");
		System.out.println("  Generating Trust Keystore...");
		KeyStore truststore = createTrustJKS("cacert",  truststorePasswd, caCert);
		fos = new FileOutputStream(outPath+ File.separator + "truststore.jks");
		truststore.store(fos, truststorePasswd.toCharArray());
		fos.close();
		System.out.println("  Trust Keystore Generated Successfully.");
		System.out.println("  Generating Test Client (testclient.jks) Keystore...");		
		KeyPair testClientKeys = keygen.generateKeyPair();		
	    ArrayList<String> testClientEKU = new ArrayList<String>();
	    sSLServerEKU.add("1.3.6.1.5.5.7.3.2");	
	    X509Name testClientName = new X509Name("CN=testclient");
		X509Certificate testClientCert = genCert(issuerDN, testClientName, 3650, cAKeys.getPrivate(), testClientKeys.getPublic(), false, X509KeyUsage.digitalSignature + X509KeyUsage.keyEncipherment,testClientEKU);
		KeyStore testclient = createUserJKS("testclient", testClientKeys.getPrivate(), testClientPasswd, testClientCert, cacerts);
		fos = new FileOutputStream(outPath+ File.separator + "testclient.jks");
		testclient.store(fos, testClientPasswd.toCharArray());
		fos.close();
		System.out.println("   Test Client Keystore Generated Successfully.");
		System.out.println("\nAll Keystores where succesfully generated to the directory : " + outPath);
	}



	private void writeCACertToPEM(X509Certificate caCert, String outPath) throws IOException, CertificateEncodingException {
		FileOutputStream fos = new FileOutputStream(outPath + File.separator + "cacert.pem");
		fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
		fos.write(encodeBase64(caCert.getEncoded(),true));
		fos.write("\n-----END CERTIFICATE-----".getBytes());
		fos.close();
	}

	private X509Certificate genCert(X509Name issuerDN, X509Name subjectDN, long validity,
			PrivateKey privKey, PublicKey pubKey, boolean isCA, int keyUsage, List<String> extendedKeyUsage) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, SignatureException {
		
		   // Create self signed certificate
        Date firstDate = new Date();

        // Set back startdate ten minutes to avoid some problems with wrongly set clocks.
        firstDate.setTime(firstDate.getTime() - (10 * 60 * 1000));

        Date lastDate = new Date();

        // validity in days = validity*24*60*60*1000 milliseconds
        lastDate.setTime(lastDate.getTime() + (validity * (24 * 60 * 60 * 1000)));

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
        certgen.setSignatureAlgorithm("SHA1WithRSA");
        certgen.setSubjectDN(issuerDN);
        certgen.setIssuerDN(subjectDN);
        certgen.setPublicKey(pubKey);

        // Basic constranits is always critical and MUST be present at-least in CA-certificates.
        BasicConstraints bc = new BasicConstraints(isCA);
        certgen.addExtension(X509Extensions.BasicConstraints.getId(), true, bc);

        // Put critical KeyUsage in CA-certificates
        if (isCA == true) {
            X509KeyUsage ku = new X509KeyUsage(keyUsage);
            certgen.addExtension(X509Extensions.KeyUsage.getId(), true, ku);
        }else{
            X509KeyUsage ku = new X509KeyUsage(keyUsage);
            certgen.addExtension(X509Extensions.KeyUsage.getId(), false, ku);
        }
        
        if(extendedKeyUsage != null){        	        
        	Vector<DERObjectIdentifier> usage = new Vector<DERObjectIdentifier>();
        	Iterator<String> iter = extendedKeyUsage.iterator();
        	while (iter.hasNext()) {
        		usage.add(new DERObjectIdentifier((String)iter.next()));
        	}
            // Don't add empty key usage extension
            if (!usage.isEmpty()) {
                ExtendedKeyUsage eku = new ExtendedKeyUsage(usage);
                // Extended Key Usage may be either critical or non-critical
                certgen.addExtension(
                    X509Extensions.ExtendedKeyUsage.getId(),
                    false,
                    eku);            	
            }
        }

        // Subject and Authority key identifier is always non-critical and MUST be present for certificates to verify in Mozilla.
        try {
            if (isCA == true) {
                SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(
                            new ByteArrayInputStream(pubKey.getEncoded())).readObject());
                SubjectKeyIdentifier ski = new SubjectKeyIdentifier(spki);

                SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(
                            new ByteArrayInputStream(pubKey.getEncoded())).readObject());
                AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);

                certgen.addExtension(X509Extensions.SubjectKeyIdentifier.getId(), false, ski);
                certgen.addExtension(X509Extensions.AuthorityKeyIdentifier.getId(), false, aki);
            }
        } catch (IOException e) { // do nothing
        }


        X509Certificate selfcert = certgen.generate(privKey);

        return selfcert;
	}
	
    public KeyStore createUserJKS(String alias, PrivateKey privKey, String password,
            X509Certificate cert, Certificate[] cachain) throws Exception {
            
            String caAlias = "cacert";

            // Certificate chain
            if (cert == null) {
                throw new IllegalArgumentException("Parameter cert cannot be null.");
            }
            int len = 1;
            if (cachain != null) {
                len += cachain.length;
            }
            Certificate[] chain = new Certificate[len];
            chain[0] = cert;
            if (cachain != null) {
                for (int i = 0; i < cachain.length; i++) {
                    chain[i + 1] = cachain[i];
                }
            }

            // store the key and the certificate chain
            KeyStore store = KeyStore.getInstance("JKS");
            store.load(null, null);

            // First load the key entry
            X509Certificate[] usercert = new X509Certificate[1];
            usercert[0] = cert;
            store.setKeyEntry(alias, privKey, password.toCharArray(), usercert);

            // Add the root cert as trusted
            if (cachain != null) {
                store.setCertificateEntry(caAlias, cachain[cachain.length - 1]);
            }

            // Set the complete chain            
            store.setKeyEntry(alias, privKey, password.toCharArray(), chain);
            
            return store;
        } // createJKS
    
    public KeyStore createTrustJKS(String alias, String password,
            X509Certificate cert) throws Exception {


            // Certificate chain
            if (cert == null) {
                throw new IllegalArgumentException("Parameter cert cannot be null.");
            }
 

            // store the key and the certificate chain
            KeyStore store = KeyStore.getInstance("JKS");
            store.load(null, null);

            // First load the key entry
            store.setCertificateEntry(alias, cert);

            return store;
        } // createJKS

	private static void displayUsageAndExit() {
		System.out.println("Usage : java -jar genservercert.jar <IssuerDN> <SubjectDN> <Output Path> <tomcat.jks passwd> <truststore.jks passwd> <testclient.jks passwd>\n\n"+
				           "  Where:\n" +
				           "    IssuerDN              : Name of the CA certificate.\n" +
				           "    SubjectDN             : Name of the SSL Server certificate.\n" +
				           "    Output Path           : Directory to place the files.\n" +
				           "    tomcat.jks passwd     : Password of the generated tomcat.jks file.\n" +
				           "    truststore.jks passwd : Password of the generated truststore.jks file.\n" +
				           "    testclient.jks passwd : Password of the generated testclient.jks file.\n" +
				           "\n" +
				           "  This program will generate a tomcat.jks, a CA certificate, a truststore.jks and" +
				           "  a testclient.jks keystore placed in the output directory.");
		System.exit(-1);
	}
	
    public static byte[] encodeBase64(byte[] data, boolean splitlines) {
		byte[] bytes = org.bouncycastle.util.encoders.Base64.encode(data);
        if (!splitlines) {
            return bytes;
        }

        // make sure we get limited lines...
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        for (int i = 0; i < bytes.length; i += 64) {
            if ((i + 64) < bytes.length) {
                os.write(bytes, i, 64);
                os.write('\n');
            } else {
                os.write(bytes, i, bytes.length - i);
            }
        }
        return os.toByteArray();
    }

}
