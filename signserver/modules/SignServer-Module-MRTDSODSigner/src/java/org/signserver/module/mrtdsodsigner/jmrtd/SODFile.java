/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2010  The JMRTD team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * $Id$
 */

package org.signserver.module.mrtdsodsigner.jmrtd;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import net.sourceforge.scuba.tlv.BERTLVInputStream;
import net.sourceforge.scuba.tlv.BERTLVObject;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.icao.DataGroupHash;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.signserver.module.mrtdsodsigner.bc.asn1.icao.LDSSecurityObject;
import org.signserver.module.mrtdsodsigner.bc.asn1.icao.LDSVersionInfo;

/**
 * File structure for the EF_SOD (Security Object Data) file.
 * This file contains the security object.
 * 
 * @author Wojciech Mostowski (woj@cs.ru.nl)
 * @author Martijn Oostdijk (martijn.oostdijk@gmail.com)
 * 
 * @version $Revision: 1270 $
 */
public class SODFile extends PassportFile
{
	//	private static final DERObjectIdentifier SHA1_HASH_ALG_OID = new DERObjectIdentifier("1.3.14.3.2.26");
	//	private static final DERObjectIdentifier SHA1_WITH_RSA_ENC_OID = new DERObjectIdentifier("1.2.840.113549.1.1.5");
	//	private static final DERObjectIdentifier SHA256_HASH_ALG_OID = new DERObjectIdentifier("2.16.840.1.101.3.4.2.1");
	//	private static final DERObjectIdentifier E_CONTENT_TYPE_OID = new DERObjectIdentifier("1.2.528.1.1006.1.20.1");

	private static final ASN1ObjectIdentifier ICAO_SOD_OID = new ASN1ObjectIdentifier("2.23.136.1.1.1");
	private static final ASN1ObjectIdentifier SIGNED_DATA_OID = new ASN1ObjectIdentifier("1.2.840.113549.1.7.2");
	private static final ASN1ObjectIdentifier RFC_3369_CONTENT_TYPE_OID = new ASN1ObjectIdentifier("1.2.840.113549.1.9.3");
	private static final ASN1ObjectIdentifier RFC_3369_MESSAGE_DIGEST_OID = new ASN1ObjectIdentifier("1.2.840.113549.1.9.4");

	private static final ASN1ObjectIdentifier PKCS1_RSA_OID = new ASN1ObjectIdentifier("1.2.840.113549.1.1.1");
	private static final ASN1ObjectIdentifier PKCS1_MD2_WITH_RSA_OID = new ASN1ObjectIdentifier("1.2.840.113549.1.1.2");
	private static final ASN1ObjectIdentifier PKCS1_MD4_WITH_RSA_OID = new ASN1ObjectIdentifier("1.2.840.113549.1.1.3");
	private static final ASN1ObjectIdentifier PKCS1_MD5_WITH_RSA_OID = new ASN1ObjectIdentifier("1.2.840.113549.1.1.4");
	private static final ASN1ObjectIdentifier PKCS1_SHA1_WITH_RSA_OID = new ASN1ObjectIdentifier("1.2.840.113549.1.1.5");
    private static final ASN1ObjectIdentifier PKCS1_MGF1_OID = new ASN1ObjectIdentifier("1.2.840.113549.1.1.8");
    private static final ASN1ObjectIdentifier PKCS1_RSA_PSS_OID = new ASN1ObjectIdentifier("1.2.840.113549.1.1.10");
	private static final ASN1ObjectIdentifier PKCS1_SHA256_WITH_RSA_OID = new ASN1ObjectIdentifier("1.2.840.113549.1.1.11");
	private static final ASN1ObjectIdentifier PKCS1_SHA384_WITH_RSA_OID = new ASN1ObjectIdentifier("1.2.840.113549.1.1.12");
	private static final ASN1ObjectIdentifier PKCS1_SHA512_WITH_RSA_OID = new ASN1ObjectIdentifier("1.2.840.113549.1.1.13");
	private static final ASN1ObjectIdentifier PKCS1_SHA224_WITH_RSA_OID = new ASN1ObjectIdentifier("1.2.840.113549.1.1.14");
	private static final ASN1ObjectIdentifier X9_SHA1_WITH_ECDSA_OID = new ASN1ObjectIdentifier("1.2.840.10045.4.1");
	private static final ASN1ObjectIdentifier X9_SHA224_WITH_ECDSA_OID = new ASN1ObjectIdentifier("1.2.840.10045.4.3.1");
	private static final ASN1ObjectIdentifier X9_SHA256_WITH_ECDSA_OID = new ASN1ObjectIdentifier("1.2.840.10045.4.3.2");
	private static final ASN1ObjectIdentifier IEEE_P1363_SHA1_OID = new ASN1ObjectIdentifier("1.3.14.3.2.26");

    private static final HashMap<String, ASN1Encodable> algorithmParameters =
    		new HashMap<String, ASN1Encodable>();

	private static final Provider PROVIDER = new org.bouncycastle.jce.provider.BouncyCastleProvider();

	private static final Logger LOGGER = Logger.getLogger("org.jmrtd");
        
        static {
        	
            algorithmParameters.put("SHA1withRSAandMGF1", new RSASSAPSSparams(
                    new AlgorithmIdentifier(X509ObjectIdentifiers.id_SHA1,
                        new DERNull()),
                    new AlgorithmIdentifier(PKCS1_MGF1_OID, 
                    new AlgorithmIdentifier(X509ObjectIdentifiers.id_SHA1,
                        new DERNull())),
                    new ASN1Integer(20), new ASN1Integer(1)));
            
            algorithmParameters.put("SHA224withRSAandMGF1", new RSASSAPSSparams(
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224,
                        new DERNull()),
                    new AlgorithmIdentifier(PKCS1_MGF1_OID, 
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224,
                        new DERNull())),
                    new ASN1Integer(28), new ASN1Integer(1)));
            
            algorithmParameters.put("SHA256withRSAandMGF1", new RSASSAPSSparams(
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256,
                        new DERNull()),
                    new AlgorithmIdentifier(PKCS1_MGF1_OID, 
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256,
                        new DERNull())),
                    new ASN1Integer(32), new ASN1Integer(1)));
            
            algorithmParameters.put("SHA384withRSAandMGF1", new RSASSAPSSparams(
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384,
                        new DERNull()),
                    new AlgorithmIdentifier(PKCS1_MGF1_OID, 
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384,
                        new DERNull())),
                    new ASN1Integer(48), new ASN1Integer(1)));
            
            algorithmParameters.put("SHA512withRSAandMGF1", new RSASSAPSSparams(
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512,
                        new DERNull()),
                    new AlgorithmIdentifier(PKCS1_MGF1_OID, 
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512,
                        new DERNull())),
                    new ASN1Integer(64), new ASN1Integer(1)));
        }

	private SignedData signedData;

	/**
	 * Constructs a Security Object data structure.
	 *
	 * @param digestAlgorithm a digest algorithm, such as "SHA1" or "SHA256"
	 * @param digestEncryptionAlgorithm a digest encryption algorithm, such as "SHA256withRSA"
	 * @param dataGroupHashes maps datagroupnumbers (1 to 16) to hashes of the data groups
	 * @param encryptedDigest the signature (the encrypted digest) over the hashes.
	 * @param docSigningCertificate the document signing certificate
	 * 
	 * @throws NoSuchAlgorithmException if either of the algorithm parameters is not recognized
	 * @throws CertificateException if the document signing certificate cannot be used
         * @deprecated Usage of this constructor is unclear. Also currently it will not work with RSASSA-PSS signatures.
	 */
        @Deprecated
	public SODFile(String digestAlgorithm, String digestEncryptionAlgorithm,
			Map<Integer, byte[]> dataGroupHashes,
			byte[] encryptedDigest,
			X509Certificate docSigningCertificate)
	throws NoSuchAlgorithmException, CertificateException, IOException {
		signedData = createSignedData(digestAlgorithm,
				digestEncryptionAlgorithm,
				dataGroupHashes,
				encryptedDigest,
				docSigningCertificate);
	}

    /**
     * Constructs a Security Object data structure using a specified signature provider.
     *
     * @param digestAlgorithm a digest algorithm, such as "SHA1" or "SHA256"
     * @param digestEncryptionAlgorithm a digest encryption algorithm, such as "SHA256withRSA"
     * @param dataGroupHashes maps datagroup numbers (1 to 16) to hashes of the data groups
     * @param privateKey private key to sign the data
     * @param docSigningCertificate the document signing certificate
     * @param provider specific signature provider that should be used to create the signature 
     * 
     * @throws NoSuchAlgorithmException if either of the algorithm parameters is not recognized
     * @throws CertificateException if the document signing certificate cannot be used
     */
    public SODFile(String digestAlgorithm, String digestEncryptionAlgorithm,
            Map<Integer, byte[]> dataGroupHashes,
            PrivateKey privateKey,
            X509Certificate docSigningCertificate, String provider)
    throws NoSuchAlgorithmException, CertificateException, IOException {
        signedData = createSignedData(digestAlgorithm,
                digestEncryptionAlgorithm,
                dataGroupHashes,
                privateKey,
                docSigningCertificate, provider);
    }

    /**
     * Constructs a Security Object data structure using a specified signature provider.
     *
     * @param digestAlgorithm a digest algorithm, such as "SHA1" or "SHA256"
     * @param digestEncryptionAlgorithm a digest encryption algorithm, such as "SHA256withRSA"
     * @param dataGroupHashes maps datagroup numbers (1 to 16) to hashes of the data groups
     * @param privateKey private key to sign the data
     * @param docSigningCertificate the document signing certificate
     * @param provider specific signature provider that should be used to create the signature
     * @param ldsVersion version of the Logical Data Structure (LDS) in the format "aabb". (Example: 1.8 becomes "0108".) Before LDS version 1.8 this should be null.
     * @param unicodeVersion version of the Unicode Standard in the format "aabbcc". (Example: 4.0.0 becomes "040000".) Before LDS version 1.8 this should be null.
     *
     * @throws NoSuchAlgorithmException if either of the algorithm parameters is not recognized
     * @throws CertificateException if the document signing certificate cannot be used
     */
    public SODFile(String digestAlgorithm, String digestEncryptionAlgorithm,
            Map<Integer, byte[]> dataGroupHashes,
            PrivateKey privateKey,
            X509Certificate docSigningCertificate, String provider,
            String ldsVersion, String unicodeVersion)
    throws NoSuchAlgorithmException, CertificateException, IOException {
        signedData = createSignedData(digestAlgorithm,
                digestEncryptionAlgorithm,
                dataGroupHashes,
                privateKey,
                docSigningCertificate, provider, ldsVersion, unicodeVersion);
    }

    /**
     * Constructs a Security Object data structure.
     *
     * @param digestAlgorithm a digest algorithm, such as "SHA1" or "SHA256"
     * @param digestEncryptionAlgorithm a digest encryption algorithm, such as "SHA256withRSA"
     * @param dataGroupHashes maps datagroup numbers (1 to 16) to hashes of the data groups
     * @param privateKey private key to sign the data
     * @param docSigningCertificate the document signing certificate
     * 
     * @throws NoSuchAlgorithmException if either of the algorithm parameters is not recognized
     * @throws CertificateException if the document signing certificate cannot be used
     */
    public SODFile(String digestAlgorithm, String digestEncryptionAlgorithm,
            Map<Integer, byte[]> dataGroupHashes,
            PrivateKey privateKey,
            X509Certificate docSigningCertificate)
    throws NoSuchAlgorithmException, CertificateException, IOException {
        signedData = createSignedData(digestAlgorithm,
                digestEncryptionAlgorithm,
                dataGroupHashes,
                privateKey,
                docSigningCertificate, null);
    }

	/**
	 * Constructs a Security Object data structure.
	 *
	 * @param in some inputstream
	 * @throws IOException if something goes wrong
	 */
	public SODFile(InputStream in) throws IOException {
		BERTLVInputStream tlvIn = new BERTLVInputStream(in);
		tlvIn.readTag();
		tlvIn.readLength();
		ASN1InputStream asn1in = new ASN1InputStream(in);
		ASN1Sequence seq = (ASN1Sequence) asn1in.readObject();
		/* DERObjectIdentifier objectIdentifier = (DERObjectIdentifier) seq.getObjectAt(0); */ /* FIXME: do we need this? */
			//DERTaggedObject o = (DERTaggedObject)seq.getObjectAt(1);
			/* TODO: where is this tagNo specified? */
		// int tagNo =  o.getTagNo();
		ASN1Sequence s2 = (ASN1Sequence)((DERTaggedObject)seq.getObjectAt(1)).getObject();			
			
		this.signedData = SignedData.getInstance(s2);
	}

	/**
	 * The tag of this file.
	 * 
	 * @return the tag
	 */
	public int getTag() {
		return EF_SOD_TAG;
	}

	public byte[] getEncoded() throws IOException {
		if (isSourceConsistent) {
			return sourceObject;
		}

		/* TODO: where is that DERTaggedObject specified? */
		ASN1Encodable[] fileContents = { SIGNED_DATA_OID, new DERTaggedObject(0, signedData) };
		ASN1Sequence fileContentsObject = new DERSequence(fileContents);
		BERTLVObject sodFile = new BERTLVObject(EF_SOD_TAG, fileContentsObject.getEncoded(), false);
		return sodFile.getEncoded();
	}

	/**
	 * Gets the stored data group hashes.
	 *
	 * @return data group hashes indexed by data group numbers (1 to 16)
	 */
	public Map<Integer, byte[]> getDataGroupHashes() {
		DataGroupHash[] hashObjects = getSecurityObject(signedData).getDatagroupHash();
		Map<Integer, byte[]> hashMap = new HashMap<Integer, byte[]>(); /* HashMap... get it? :D */
		for (int i = 0; i < hashObjects.length; i++) {
			DataGroupHash hashObject = hashObjects[i];
			int number = hashObject.getDataGroupNumber();
			byte[] hashValue = hashObject.getDataGroupHashValue().getOctets();
			hashMap.put(number, hashValue);
		}
		return hashMap;
	}

	/**
	 * Gets the signature (the encrypted digest) over the hashes.
	 *
	 * @return the encrypted digest
	 */
	public byte[] getEncryptedDigest() {
		return getEncryptedDigest(signedData);
	}

	/**
	 * Gets the name of the algorithm used in the data group hashes.
	 * 
	 * @return an algorithm string such as "SHA1" or "SHA256"
	 */
	public String getDigestAlgorithm() {
		try {
			return lookupMnemonicByOID(getSecurityObject(signedData).getDigestAlgorithmIdentifier().getAlgorithm());      
		} catch (NoSuchAlgorithmException nsae) {
			nsae.printStackTrace();
			throw new IllegalStateException(nsae.toString());
		}
	}

	/**
	 * Gets the name of the algorithm used in the signature.
	 * 
	 * @return an algorithm string such as "SHA256withRSA"
	 */
	public String getDigestEncryptionAlgorithm() {
		try {
                    final DERObjectIdentifier algorithm = getSignerInfo(signedData).getDigestEncryptionAlgorithm().getAlgorithm();
                    String result = lookupMnemonicByOID(algorithm);
                    if (PKCS1_RSA_PSS_OID.toString().equals(algorithm.toString())) {
                        try {
                            final ASN1Encodable parameters = getSignerInfo(signedData).getDigestEncryptionAlgorithm().getParameters();
                            if (parameters != null) {
                                AlgorithmParameters params = AlgorithmParameters.getInstance("PSS");
                                params.init(parameters.toASN1Primitive().getEncoded());
                                final PSSParameterSpec spec = params.getParameterSpec(PSSParameterSpec.class);
                                result = lookupMnemonicByOID(new DERObjectIdentifier(spec.getDigestAlgorithm())) + "withRSAand" + lookupMnemonicByOID(new DERObjectIdentifier(spec.getMGFAlgorithm()));
                            }
                        } catch (InvalidParameterSpecException ignored) {}
                        catch (IOException ignored) {}
                    }
                    return result;
		} catch (NoSuchAlgorithmException nsae) {
			nsae.printStackTrace();
			throw new IllegalStateException(nsae.toString());
		}
	}

        /**
	 * Gets the version of the LDS if stored in the Security Object (SOd).
	 *
	 * @return the version of the LDS in "aabb" format or null if LDS &lt; V1.8
         * @since LDS V1.8
	 */
	public String getLdsVersion() {
            LDSVersionInfo ldsVersionInfo = getSecurityObject(signedData).getLdsVersionInfo();
            if (ldsVersionInfo == null) {
                return null;
            } else {
                return ldsVersionInfo.getLdsVersion();
            }
	}

        /**
	 * Gets the version of unicode if stored in the Security Object (SOd).
	 *
	 * @return the unicode version in "aabbcc" format or null if LDS &lt; V1.8
         * @since LDS V1.8
	 */
	public String getUnicodeVersion() {
            LDSVersionInfo ldsVersionInfo = getSecurityObject(signedData).getLdsVersionInfo();
            if (ldsVersionInfo == null) {
                return null;
            } else {
                return ldsVersionInfo.getUnicodeVersion();
            }
	}

	/**
	 * Gets the document signing certificate.
	 * Use this certificate to verify that
	 * <i>eSignature</i> is a valid signature for
	 * <i>eContent</i>. This certificate itself is
	 * signed using the country signing certificate.
     * 
	 * @return the document signing certificate
	 */
	public X509Certificate getDocSigningCertificate()
	throws IOException, CertificateException {
		ASN1Set certs = signedData.getCertificates();
		if (certs == null || certs.size() <= 0) { return null; }
		if (certs.size() != 1) {
			LOGGER.warning("Found " + certs.size() + " certificates");
		}
        final X509CertificateHolder cert = new X509CertificateHolder(certs.getObjectAt(0).toASN1Primitive().getEncoded());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);
	}

	/**
	 * Verifies the signature over the contents of the security object.
	 * Clients can also use the accessors of this class and check the
	 * validity of the signature for themselves.
	 * 
	 * See RFC 3369, Cryptographic Message Syntax, August 2002,
	 * Section 5.4 for details.
	 * 
	 * @param docSigningCert the certificate to use
	 *        (should be X509 certificate)
	 * 
	 * @return status of the verification
	 * 
	 * @throws GeneralSecurityException if something goes wrong
	 */
	public boolean checkDocSignature(Certificate docSigningCert)
	throws GeneralSecurityException {
		byte[] eContent = null;       
		byte[] signature = getEncryptedDigest(signedData);

		try {
			eContent = getEContent(signedData);
		} catch (IOException ioe) {
			throw new GeneralSecurityException("Unable to get the contents of the security object", ioe);
		}
		
		DERObjectIdentifier encAlgId = getSignerInfo(signedData).getDigestEncryptionAlgorithm().getAlgorithm();
		String encAlgJavaString = lookupMnemonicByOID(encAlgId);

		// For the cases where the signature is simply a digest (haven't seen a passport like this, 
		// thus this is guessing)

		if (encAlgId.getId() == null) {
			String digestAlg = getSignerInfo(signedData).getDigestAlgorithm().getAlgorithm().getId();
			MessageDigest digest = null;
			try {
				digest = MessageDigest.getInstance(digestAlg);
			} catch (Exception e) {
				/* FIXME: Warn client that they should perhaps add BC as provider? */
				digest = MessageDigest.getInstance(digestAlg, PROVIDER);
			}
			digest.update(eContent);
			byte[] digestBytes = digest.digest();
			return Arrays.equals(digestBytes, signature);
		}

		if (encAlgId.equals(PKCS1_RSA_OID)) {
			encAlgJavaString = lookupMnemonicByOID(getSignerInfo(signedData).getDigestAlgorithm().getAlgorithm())
			+ "withRSA";
		}

		Signature sig = null;
		try {
			sig = Signature.getInstance(encAlgJavaString);
		} catch (Exception e) {
			/* FIXME: Warn client that they should perhaps add BC as provider? */
			sig = Signature.getInstance(encAlgJavaString, PROVIDER);
		}
                if (encAlgId.equals(PKCS1_RSA_PSS_OID)) {
                    try {
                        final ASN1Encodable parameters = getSignerInfo(signedData).getDigestEncryptionAlgorithm().getParameters();
                        if (parameters != null) {
                            AlgorithmParameters params = AlgorithmParameters.getInstance("PSS");
                            params.init(parameters.toASN1Primitive().getEncoded());
                            sig.setParameter(params.getParameterSpec(PSSParameterSpec.class));
                        }
                    } catch (IOException ex) {
                        throw new GeneralSecurityException("Unable to parse algorithm parameters", ex);
                    }
                }
		sig.initVerify(docSigningCert);
		sig.update(eContent);
		return sig.verify(signature);

		// 2. Do it manually, decrypt the signature and extract the hashing algorithm
		/*
		try {
			Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			c.init(Cipher.DECRYPT_MODE, docSigningCert);
			c.update(signature);
			byte[] decryptedBytes = c.doFinal();
			String id = getHashId(decryptedBytes);
			byte[] expectedHash = getHashBytes(decryptedBytes);
			MessageDigest digest = MessageDigest.getInstance(id);
			digest.update(eContent);
			byte[] digestBytes = digest.digest();
			result = Arrays.equals(digestBytes, expectedHash);
		}catch(Exception e) {

		}
        String[] sigAlgs = new String[] {"SHA1withRSA", "SHA1withRSA/PSS", "SHA256withRSA", "SHA256withRSA/PSS"};
		 */
	}

	public X500Principal getIssuerX500Principal() throws IOException {
		IssuerAndSerialNumber issuerAndSerialNumber = getIssuerAndSerialNumber();
		X500Name name = issuerAndSerialNumber.getName();
		
		return new X500Principal(name.getEncoded(ASN1Encoding.DER));
	}

	public BigInteger getSerialNumber() {
		IssuerAndSerialNumber issuerAndSerialNumber = getIssuerAndSerialNumber();
		BigInteger serialNumber = issuerAndSerialNumber.getSerialNumber().getValue();
		return serialNumber;
	}

	/**
	 * Gets a textual representation of this file.
	 * 
	 * @return a textual representation of this file
	 */
	public String toString() {
		try {
			X509Certificate cert = getDocSigningCertificate();
			return "SODFile " + cert.getIssuerX500Principal();
		} catch (Exception e) {
			return "SODFile";
		}
	}

	public boolean equals(Object obj) {
		if (obj == null) { return false; }
		if (obj == this) { return true; }
		if (!obj.getClass().equals(this.getClass())) { return false; }
		SODFile other = (SODFile)obj;
		try {
			return Arrays.equals(getEncoded(), other.getEncoded());
		} catch (IOException e) {
			// shouldn't really happen...
			return false;
		}
	}

	public int hashCode() {
		int hash = 0;
		
		try {
			hash += Arrays.hashCode(getEncoded());
		} catch (IOException e) {
			// NOPMD
		}
		
		return 11 * hash + 111;
	}

	/* ONLY PRIVATE METHODS BELOW */

	private static SignerInfo getSignerInfo(SignedData signedData)  {
		ASN1Set signerInfos = signedData.getSignerInfos();
		if (signerInfos.size() > 1) {
			LOGGER.warning("Found " + signerInfos.size() + " signerInfos");
		}
		for (int i = 0; i < signerInfos.size(); i++) {
			SignerInfo info = new SignerInfo((DERSequence)signerInfos.getObjectAt(i));
			return info;
		}
		return null;
	}

	/**
	 * Reads the security object (containing the hashes
	 * of the data groups) found in the SOd on the passport.
	 * 
	 * @return the security object
	 * 
	 * @throws IOException
	 */
	private static LDSSecurityObject getSecurityObject(SignedData signedData) {
		try {
			ContentInfo contentInfo = signedData.getEncapContentInfo();
			byte[] content = ((DEROctetString)contentInfo.getContent()).getOctets();
			ASN1InputStream in =
				new ASN1InputStream(new ByteArrayInputStream(content)); 

			LDSSecurityObject sod =
				new LDSSecurityObject((ASN1Sequence)in.readObject());
			Object nextObject = in.readObject();

			if (nextObject != null) {
				LOGGER.warning("extra object found after LDSSecurityObject...");
			}
			return sod;
		} catch (IOException ioe) {
			throw new IllegalStateException("Could not read security object in signedData");
		}
	}

	/**
	 * Gets the contents of the security object over which the
	 * signature is to be computed. 
	 * 
	 * See RFC 3369, Cryptographic Message Syntax, August 2002,
	 * Section 5.4 for details.
	 * 
	 * FIXME: Maybe throw an exception instead of issuing warnings
	 * on stderr if signed attributes don't check out.
	 *
	 * @see #getDocSigningCertificate()
	 * @see #getSignature()
	 * 
	 * @return the contents of the security object over which the
	 *         signature is to be computed
	 */
	private static byte[] getEContent(SignedData signedData) throws IOException {
		SignerInfo signerInfo = getSignerInfo(signedData);
		ASN1Set signedAttributesSet = signerInfo.getAuthenticatedAttributes();

		ContentInfo contentInfo = signedData.getEncapContentInfo();
		byte[] contentBytes = ((DEROctetString)contentInfo.getContent()).getOctets();

		if (signedAttributesSet.size() == 0) {
			/* Signed attributes absent, return content to be signed... */
			return contentBytes;
		} else {
			/* Signed attributes present (i.e. a structure containing a hash of the content), return that structure to be signed... */
			/* This option is taken by ICAO passports. */
			byte[] attributesBytes = signedAttributesSet.getEncoded();
			String digAlg = signerInfo.getDigestAlgorithm().getAlgorithm().getId();
			try {
				/* We'd better check that the content actually digests to the hash value contained! ;) */
				Enumeration<?> attributes = signedAttributesSet.getObjects();
				byte[] storedDigestedContent = null;
				while (attributes.hasMoreElements()) {
					Attribute attribute = Attribute.getInstance(attributes.nextElement());
					DERObjectIdentifier attrType = attribute.getAttrType();
					if (attrType.equals(RFC_3369_MESSAGE_DIGEST_OID)) {
						ASN1Set attrValuesSet = attribute.getAttrValues();
						if (attrValuesSet.size() != 1) {
							LOGGER.warning("Expected only one attribute value in signedAttribute message digest in eContent!");
						}
						storedDigestedContent = ((DEROctetString)attrValuesSet.getObjectAt(0)).getOctets();
					}
				}
				if (storedDigestedContent == null) {
					LOGGER.warning("Error extracting signedAttribute message digest in eContent!");
				}	
				MessageDigest dig = MessageDigest.getInstance(digAlg);
				byte[] computedDigestedContent = dig.digest(contentBytes);
				if (!Arrays.equals(storedDigestedContent, computedDigestedContent)) {
					LOGGER.warning("Error checking signedAttribute message digest in eContent!");
				}
			} catch (NoSuchAlgorithmException nsae) {
				LOGGER.warning("Error checking signedAttribute in eContent! No such algorithm " + digAlg);
			}
			return attributesBytes;
		}
	}

	private IssuerAndSerialNumber getIssuerAndSerialNumber() {
		SignerInfo signerInfo = getSignerInfo(signedData);
		SignerIdentifier signerIdentifier = signerInfo.getSID();
		DERSequence idSeq = (DERSequence)signerIdentifier.getId();
		IssuerAndSerialNumber issuerAndSerialNumber = IssuerAndSerialNumber.getInstance(idSeq);
		return issuerAndSerialNumber;
	}

	/**
	 * Gets the stored signature of the security object.
	 * 
	 * @see #getDocSigningCertificate()
	 * 
	 * @return the signature
	 */
	private static byte[] getEncryptedDigest(SignedData signedData) {
		SignerInfo signerInfo = getSignerInfo(signedData);
		return signerInfo.getEncryptedDigest().getOctets();
	}

	/* METHODS BELOW ARE FOR CONSTRUCTING SOD STRUCTS */

	private static SignedData createSignedData(
			String digestAlgorithm,
			String digestEncryptionAlgorithm,
			Map<Integer, byte[]> dataGroupHashes,
			byte[] encryptedDigest,
			X509Certificate docSigningCertificate)
	throws NoSuchAlgorithmException, CertificateException, IOException {
		ASN1Set digestAlgorithmsSet = createSingletonSet(createDigestAlgorithms(digestAlgorithm));
		ContentInfo contentInfo = createContentInfo(digestAlgorithm, dataGroupHashes);
		byte[] content = ((DEROctetString)contentInfo.getContent()).getOctets();
		ASN1Set certificates =  createSingletonSet(createCertificate(docSigningCertificate));
		ASN1Set crls = null;
		ASN1Set signerInfos = createSingletonSet(createSignerInfo(digestAlgorithm,
												digestEncryptionAlgorithm, null,
												content, encryptedDigest, docSigningCertificate).toASN1Primitive());
		return new SignedData(digestAlgorithmsSet, contentInfo, certificates, crls, signerInfos);
	}

    private static SignedData createSignedData(String digestAlgorithm,
            String digestEncryptionAlgorithm,
            Map<Integer, byte[]> dataGroupHashes, PrivateKey privateKey,
            X509Certificate docSigningCertificate, String provider)
            throws NoSuchAlgorithmException, CertificateException, IOException {
        return createSignedData(digestAlgorithm, digestEncryptionAlgorithm,
                dataGroupHashes, privateKey, docSigningCertificate, provider,
                null, null);
    }

    private static SignedData createSignedData(String digestAlgorithm,
            String digestEncryptionAlgorithm,
            Map<Integer, byte[]> dataGroupHashes, PrivateKey privateKey,
            X509Certificate docSigningCertificate, String provider,
            String ldsVersion, String unicodeVersion)
            throws NoSuchAlgorithmException, CertificateException, IOException {
        ASN1Set digestAlgorithmsSet = createSingletonSet(createDigestAlgorithms(digestAlgorithm));
        ContentInfo contentInfo = createContentInfo(digestAlgorithm,
                        dataGroupHashes, ldsVersion, unicodeVersion);
        byte[] content = ((DEROctetString) contentInfo.getContent())
                .getOctets();

        ASN1Encodable digestEncryptionAlgorithmParams;
        byte[] encryptedDigest = null;
        try {
            byte[] dataToBeSigned = createAuthenticatedAttributes(
                    digestAlgorithm, content).getEncoded(ASN1Encoding.DER);
            Signature s;
            if (provider != null) {
                s = Signature.getInstance(digestEncryptionAlgorithm, provider);
            } else {
                s = Signature.getInstance(digestEncryptionAlgorithm);
            }
            s.initSign(privateKey);
            s.update(dataToBeSigned);
            encryptedDigest = s.sign();
            if (PKCS1_RSA_PSS_OID.toString().equals(
                lookupOIDByMnemonic(digestEncryptionAlgorithm).toString())) {
//                try {
//                    digestEncryptionAlgorithmParams = ASN1Object.fromByteArray(
//                            s.getParameters().getEncoded());
//                } catch (UnsupportedOperationException ex) {
//                    // Some providers does not support getting the parameters
//                    // (i.e. SunPKCS11 provider). Instead we assume they
//                    // use the default parameters.
                    digestEncryptionAlgorithmParams =
                            algorithmParameters.get(digestEncryptionAlgorithm);
//                }
            } else {
                digestEncryptionAlgorithmParams = null;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        ASN1Set certificates = createSingletonSet(createCertificate(docSigningCertificate));
        ASN1Set crls = null;
        ASN1Set signerInfos = createSingletonSet(createSignerInfo(
                digestAlgorithm, digestEncryptionAlgorithm, digestEncryptionAlgorithmParams, content,
                encryptedDigest, docSigningCertificate).toASN1Primitive());
        return new SignedData(digestAlgorithmsSet, contentInfo, certificates,
                crls, signerInfos);
    }

	private static ASN1Sequence createDigestAlgorithms(String digestAlgorithm) throws NoSuchAlgorithmException {
		DERObjectIdentifier algorithmIdentifier = lookupOIDByMnemonic(digestAlgorithm);
		ASN1Encodable[] result = { algorithmIdentifier };
		return new DERSequence(result);
	}

	private static ASN1Sequence createCertificate(X509Certificate cert) throws CertificateException {
		try {
			byte[] certSpec = cert.getEncoded();
			ASN1InputStream asn1In = new ASN1InputStream(certSpec);
			try {
				ASN1Sequence certSeq = (ASN1Sequence)(asn1In).readObject();
				return certSeq;
			} finally {
				asn1In.close();
			}
		} catch (IOException ioe) {
			throw new CertificateException("Could not construct certificate byte stream");
		}
	}

        private static ContentInfo createContentInfo(
			String digestAlgorithm,
			Map<Integer, byte[]> dataGroupHashes)
					throws NoSuchAlgorithmException, IOException {
            return createContentInfo(digestAlgorithm, dataGroupHashes, null,
                    null);
        }

	private static ContentInfo createContentInfo(
			String digestAlgorithm,
			Map<Integer, byte[]> dataGroupHashes,
                        String ldsVersion, String unicodeVersion)
	throws NoSuchAlgorithmException, IOException {
		DataGroupHash[] dataGroupHashesArray = new DataGroupHash[dataGroupHashes.size()];
		int i = 0;
		for (int dataGroupNumber: dataGroupHashes.keySet()) {
			byte[] hashBytes = dataGroupHashes.get(dataGroupNumber);
			DataGroupHash hash = new DataGroupHash(dataGroupNumber, new DEROctetString(hashBytes));
			dataGroupHashesArray[i++] = hash;
		}
		AlgorithmIdentifier digestAlgorithmIdentifier = new AlgorithmIdentifier(lookupOIDByMnemonic(digestAlgorithm));
                LDSVersionInfo ldsVersionInfo;
                if (ldsVersion == null) {
                    ldsVersionInfo = null;
                } else {
                    ldsVersionInfo = new LDSVersionInfo(
                            new DERPrintableString(ldsVersion, true),
                            new DERPrintableString(unicodeVersion, true));
                }
		LDSSecurityObject sObject2 = new LDSSecurityObject(digestAlgorithmIdentifier, dataGroupHashesArray, ldsVersionInfo);
		return new ContentInfo(ICAO_SOD_OID, new DEROctetString(sObject2));
	}

	private static SignerInfo createSignerInfo(
			String digestAlgorithm,
			String digestEncryptionAlgorithm,
            ASN1Encodable digestEncryptionAlgorithmParams,
			byte[] content,
			byte[] encryptedDigest,
			X509Certificate docSigningCertificate)
	throws NoSuchAlgorithmException, CertificateEncodingException {
		/* Get the issuer name (CN, O, OU, C) from the cert and put it in a SignerIdentifier struct. */
		BigInteger serial = ((X509Certificate)docSigningCertificate).getSerialNumber();
		IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(JcaX500NameUtil.getIssuer(docSigningCertificate), serial);
		SignerIdentifier sid = new SignerIdentifier(iasn);
		AlgorithmIdentifier digestAlgorithmObject = new AlgorithmIdentifier(lookupOIDByMnemonic(digestAlgorithm)); 
		final AlgorithmIdentifier digestEncryptionAlgorithmObject;
                if (digestEncryptionAlgorithmParams == null) {
                    digestEncryptionAlgorithmObject = new AlgorithmIdentifier(lookupOIDByMnemonic(digestEncryptionAlgorithm));
                } else {
                    digestEncryptionAlgorithmObject = new AlgorithmIdentifier(lookupOIDByMnemonic(digestEncryptionAlgorithm), digestEncryptionAlgorithmParams);
                }

		ASN1Set authenticatedAttributes = createAuthenticatedAttributes(digestAlgorithm, content); // struct containing the hash of content
		ASN1OctetString encryptedDigestObject = new DEROctetString(encryptedDigest); // this is the signature
		ASN1Set unAuthenticatedAttributes = null; // should be empty set?
		return new SignerInfo(sid, digestAlgorithmObject, authenticatedAttributes, digestEncryptionAlgorithmObject, encryptedDigestObject, unAuthenticatedAttributes);
	}

	private static ASN1Set createAuthenticatedAttributes(String digestAlgorithm, byte[] contentBytes)
	throws NoSuchAlgorithmException {
		MessageDigest dig = MessageDigest.getInstance(digestAlgorithm);
		byte[] digestedContentBytes = dig.digest(contentBytes);
		ASN1OctetString digestedContent = new DEROctetString(digestedContentBytes);
		Attribute contentTypeAttribute = new Attribute(RFC_3369_CONTENT_TYPE_OID, createSingletonSet(ICAO_SOD_OID));
		Attribute messageDigestAttribute = new Attribute(RFC_3369_MESSAGE_DIGEST_OID, createSingletonSet(digestedContent));
		ASN1Encodable[] result = { contentTypeAttribute.toASN1Primitive(),
									messageDigestAttribute.toASN1Primitive() };
		return new DERSet(result);
	}

	private static ASN1Set createSingletonSet(ASN1Encodable e) {
		ASN1Encodable[] result = { e };
		return new DERSet(result);
	}

	/**
	 * Gets the common mnemonic string (such as "SHA1", "SHA256withRSA") given an OID.
	 *
	 * @param oid a BC OID
	 *
	 * @throws NoSuchAlgorithmException if the provided OID is not yet supported
	 */
	private static String lookupMnemonicByOID(DERObjectIdentifier oid) throws NoSuchAlgorithmException {
		if (oid.equals(X509ObjectIdentifiers.organization)) { return "O"; }
		if (oid.equals(X509ObjectIdentifiers.organizationalUnitName)) { return "OU"; }
		if (oid.equals(X509ObjectIdentifiers.commonName)) { return "CN"; }
		if (oid.equals(X509ObjectIdentifiers.countryName)) { return "C"; }
		if (oid.equals(X509ObjectIdentifiers.stateOrProvinceName)) { return "ST"; }
		if (oid.equals(X509ObjectIdentifiers.localityName)) { return "L"; }
		if(oid.equals(X509ObjectIdentifiers.id_SHA1)) { return "SHA1"; }
		if(oid.equals(NISTObjectIdentifiers.id_sha224)) { return "SHA224"; }
		if(oid.equals(NISTObjectIdentifiers.id_sha256)) { return "SHA256"; }
		if(oid.equals(NISTObjectIdentifiers.id_sha384)) { return "SHA384"; }
		if(oid.equals(NISTObjectIdentifiers.id_sha512)) { return "SHA512"; }
		if (oid.equals(X9_SHA1_WITH_ECDSA_OID)) { return "SHA1withECDSA"; }
		if (oid.equals(X9_SHA224_WITH_ECDSA_OID)) { return "SHA224withECDSA"; }
		if (oid.equals(X9_SHA256_WITH_ECDSA_OID)) { return "SHA256withECDSA"; }		
                if (oid.equals(PKCS1_MGF1_OID)) { return "MGF1"; }
		if (oid.equals(PKCS1_RSA_OID)) { return "RSA"; }
		if (oid.equals(PKCS1_MD2_WITH_RSA_OID)) { return "MD2withRSA"; }
		if (oid.equals(PKCS1_MD4_WITH_RSA_OID)) { return "MD4withRSA"; }
		if (oid.equals(PKCS1_MD5_WITH_RSA_OID)) { return "MD5withRSA"; }
		if (oid.equals(PKCS1_SHA1_WITH_RSA_OID)) { return "SHA1withRSA"; }
		if (oid.equals(PKCS1_SHA256_WITH_RSA_OID)) { return "SHA256withRSA"; }
		if (oid.equals(PKCS1_SHA384_WITH_RSA_OID)) { return "SHA384withRSA"; }
		if (oid.equals(PKCS1_SHA512_WITH_RSA_OID)) { return "SHA512withRSA"; }
		if (oid.equals(PKCS1_SHA224_WITH_RSA_OID)) { return "SHA224withRSA"; }
		if (oid.equals(IEEE_P1363_SHA1_OID)) { return "SHA1"; }
		if (oid.equals(PKCS1_RSA_PSS_OID)) { return "RSASSA-PSS"; }
		throw new NoSuchAlgorithmException("Unknown OID " + oid);
	}

	private static ASN1ObjectIdentifier lookupOIDByMnemonic(String name) throws NoSuchAlgorithmException {
		if (name.equals("O")) { return X509ObjectIdentifiers.organization; }
		if (name.equals("OU")) { return X509ObjectIdentifiers.organizationalUnitName; }
		if (name.equals("CN")) { return X509ObjectIdentifiers.commonName; }
		if (name.equals("C")) { return X509ObjectIdentifiers.countryName; }
		if (name.equals("ST")) { return X509ObjectIdentifiers.stateOrProvinceName; }
		if (name.equals("L")) { return X509ObjectIdentifiers.localityName; }
		if(name.equalsIgnoreCase("SHA1")) { return X509ObjectIdentifiers.id_SHA1; }
		if(name.equalsIgnoreCase("SHA224")) { return NISTObjectIdentifiers.id_sha224; }
		if(name.equalsIgnoreCase("SHA256")) { return NISTObjectIdentifiers.id_sha256; }
		if(name.equalsIgnoreCase("SHA384")) { return NISTObjectIdentifiers.id_sha384; }
		if(name.equalsIgnoreCase("SHA512")) { return NISTObjectIdentifiers.id_sha512; }
		if (name.equalsIgnoreCase("RSA")) { return PKCS1_RSA_OID; }
		if (name.equalsIgnoreCase("MD2withRSA")) { return PKCS1_MD2_WITH_RSA_OID; } 
		if (name.equalsIgnoreCase("MD4withRSA")) { return PKCS1_MD4_WITH_RSA_OID; } 
		if (name.equalsIgnoreCase("MD5withRSA")) { return  PKCS1_MD5_WITH_RSA_OID; }
		if (name.equalsIgnoreCase("SHA1withRSA")) { return  PKCS1_SHA1_WITH_RSA_OID; }
		if (name.equalsIgnoreCase("SHA256withRSA")) { return PKCS1_SHA256_WITH_RSA_OID; }
		if (name.equalsIgnoreCase("SHA384withRSA")) { return PKCS1_SHA384_WITH_RSA_OID; }
		if (name.equalsIgnoreCase("SHA512withRSA")) { return PKCS1_SHA512_WITH_RSA_OID; }
		if (name.equalsIgnoreCase("SHA224withRSA")) { return PKCS1_SHA224_WITH_RSA_OID; }
		if (name.equalsIgnoreCase("SHA1withECDSA")) { return X9_SHA1_WITH_ECDSA_OID; }
		if (name.equalsIgnoreCase("SHA224withECDSA")) { return X9_SHA224_WITH_ECDSA_OID; }
		if (name.equalsIgnoreCase("SHA256withECDSA")) { return X9_SHA256_WITH_ECDSA_OID; }
		if (name.equalsIgnoreCase("MGF1")) { return  PKCS1_MGF1_OID; }
                if (name.equalsIgnoreCase("SHA1withRSAandMGF1")) { return  PKCS1_RSA_PSS_OID; }
                if (name.equalsIgnoreCase("SHA224withRSAandMGF1")) { return PKCS1_RSA_PSS_OID; }
		if (name.equalsIgnoreCase("SHA256withRSAandMGF1")) { return PKCS1_RSA_PSS_OID; }
		if (name.equalsIgnoreCase("SHA384withRSAandMGF1")) { return PKCS1_RSA_PSS_OID; }
		if (name.equalsIgnoreCase("SHA512withRSAandMGF1")) { return PKCS1_RSA_PSS_OID; }
		throw new NoSuchAlgorithmException("Unknown name " + name);
	}
}
