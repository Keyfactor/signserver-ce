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

package org.signserver.server.cryptotokens;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.ejbca.util.Base64;
import org.signserver.common.IllegalRequestException;

/**
 * Class containing help methods that could be used when implementing a
 * cryptotoken
 * 
 * 
 * @author Philip Vendil 21 nov 2007
 * 
 * @version $Id$
 */

public final class CryptoTokenUtils {

    /** No instances of this class */
    private CryptoTokenUtils() {}

	/**
	 * Checks all installed key generator algorithms if the given one exists and
	 * if it is a symmetric key or asymmetric.
	 * 
	 * @param keyAlg
	 *            the key algorithm to check
	 * @return true if the algorithm is asymmetric
	 * @throws IllegalRequestException
	 *             if the given algorithm cannot be found as either symmetric or
	 *             asymmetric
	 */
	public static boolean isKeyAlgAssymmetric(String keyAlg)
			throws IllegalRequestException {
		String[] names = getCryptoImpls("KeyPairGenerator");
		for (int i = 0; i < names.length; i++) {
			if (names[i].equalsIgnoreCase(keyAlg)) {
				return true;
			}
		}
		names = getCryptoImpls("KeyGenerator");
		for (int i = 0; i < names.length; i++) {
			if (names[i].equalsIgnoreCase(keyAlg)) {
				return false;
			}
		}

		throw new IllegalRequestException("Error given key algorithm " + keyAlg
				+ " isn't supported by the system. "
				+ "Are you sure the providers are installed correctly.");
	}

	/**
	 * Method for listening different crypto implementations supported by the
	 * different installed providers.
	 */
	public static String[] getCryptoImpls(String serviceType) {
		Set<String> result = new HashSet<String>();

		// All all providers
		Provider[] providers = Security.getProviders();
		for (int i = 0; i < providers.length; i++) {
			// Get services provided by each provider
			Set<?> keys = providers[i].keySet();
			for (Iterator<?> it = keys.iterator(); it.hasNext();) {
				String key = (String) it.next();
				key = key.split(" ")[0];

				if (key.startsWith(serviceType + ".")) {
					result.add(key.substring(serviceType.length() + 1));
				} else if (key.startsWith("Alg.Alias." + serviceType + ".")) {
					// This is an alias
					result.add(key.substring(serviceType.length() + 11));
				}
			}
		}
		return (String[]) result.toArray(new String[result.size()]);
	}

	/**
	 * creates keydata from given keystore to be used as a KEYDATA property for
	 * signers using SoftCryptoToken as signature token
	 * 
	 * @param store
	 *            p12 keystore path
	 * @param sPass
	 *            keystore protection password
	 * @param kPass
	 *            private key password
	 * @param alias
	 *            alias of the signing key
	 * @return byte[] in format :
	 *         {PUBLICKEYDATASIZE(int)|PUBLICKEYDATA(byte[])|PRIVATEKEYDATASIZE
	 *         (int)|PRIVATKEYDATA(bute[])} as required by KEYDATA property
	 * @throws CertificateException
	 * @throws IOException
	 * @throws UnrecoverableKeyException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static String CreateKeyDataForSoftCryptoToken(String store,
			String sPass, String kPass, String alias)
			throws CertificateException, IOException,
			UnrecoverableKeyException, KeyStoreException,
			NoSuchAlgorithmException, NoSuchProviderException {
		KeyStore ks = loadKeyStore(store, sPass);
		Key key = null;
		PublicKey publicKey = null;
		PrivateKey privateKey = null;
		if (ks.containsAlias(alias)) {
			key = ks.getKey(alias, kPass.toCharArray());
			if (key instanceof PrivateKey) {
				Certificate cert = ks.getCertificate(alias);
				publicKey = cert.getPublicKey();
				privateKey = (PrivateKey) key;

				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				DataOutputStream dout = new DataOutputStream(bos);
				int publicKeyDataSize = publicKey.getEncoded().length;
				int privateKeyDataSize = privateKey.getEncoded().length;

				dout.writeInt(publicKeyDataSize);
				dout.write(publicKey.getEncoded());
				dout.writeInt(privateKeyDataSize);
				dout.write(privateKey.getEncoded());
				dout.flush();

				return new String(Base64.encode(bos.toByteArray(), false))
						.replace("=", "\\=");

			} else {
				return null;
			}
		} else {
			return null;
		}
	}

	/**
	 * creates certificate chain from given keystore to be used as a SIGNERCERTCHAIN
	 * property for signers using SoftCryptoToken as signature token
	 * 
	 * @param store
	 *            - p12 keystore path
	 * @param sPass
	 *            - keystore protection password
	 * @param alias
	 *            - alias of the signing key
	 * @return string containing certificate chain , each certificate delimited
	 *         by ";", and the character "=" escaped by "\" ("\=")
	 * @throws CertificateException
	 * @throws IOException
	 * @throws UnrecoverableKeyException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static String CreateSignerCertificateChainForSoftCryptoToken(String store,
			String sPass, String alias) throws CertificateException,
			IOException, UnrecoverableKeyException, KeyStoreException,
			NoSuchAlgorithmException, NoSuchProviderException {
		String retVal = new String();
		KeyStore ks = loadKeyStore(store, sPass);
		if (ks.containsAlias(alias)) {
			Certificate[] certChain = ks.getCertificateChain(alias);
			for (int i = 0; i < certChain.length; i++) {
				if (i > 0) {
					retVal += ";";
                                }

				retVal += new String(Base64.encode(certChain[i].getEncoded(),
						false)).replace("=", "\\=");
			}

			return retVal;

		} else {
			return null;
		}
	}

	/**
	 * method to load keystore from p12 file
	 * @param store - store path
	 * @param sPass - store protection pass
	 * @return 
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws NoSuchProviderException
	 * @throws CertificateException
	 */
	private static KeyStore loadKeyStore(String store, String sPass)
			throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException, NoSuchProviderException, CertificateException {
		Security
				.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		KeyStore myKS = KeyStore.getInstance("PKCS12", "BC");
		FileInputStream fis = new FileInputStream(store);
		myKS.load(fis, sPass.toCharArray());
		fis.close();
		return myKS;
	}

        /**
         * Command line tool for generating the data for a SoftCryptoToken.
         * @param args
         * @throws Exception
         */
        public static void main(String[] args) throws Exception {
            if (args.length == 4 && "createsoft".equals(args[0])) {
                System.out.println("WORKERGEN1.SIGNERCERTCHAIN=" + CreateSignerCertificateChainForSoftCryptoToken(args[1], args[3], args[2]));
                System.out.println("WORKERGEN1.KEYDATA=" + CreateKeyDataForSoftCryptoToken(args[1], args[3], args[3], args[2]));
            } else {
                System.err.println("Usage: CryptoTokenUtils createsoft <PKCS#12 keystore> <key alias> <keystore password>");
            }
        }

}
