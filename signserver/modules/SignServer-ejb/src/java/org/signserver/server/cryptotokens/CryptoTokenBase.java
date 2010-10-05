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
 
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.model.ca.catoken.CATokenAuthenticationFailedException;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.catoken.ICAToken;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.SignerStatus;
import org.signserver.common.KeyTestResult;


/**
 * A base class to wrap around CATokens from EJBCA. Makes it easy to use CA Tokens from EJBCA 
 * as crypto tokens in Signserver.
 * 
 * @see org.signserver.server.cryptotokens.ICryptoToken
 * @author Philip Vendil, Tomas Gustavsson
 * @version $Id$
 */
public abstract class CryptoTokenBase implements ICryptoToken{

	private static final Logger log = Logger.getLogger(CryptoTokenBase.class);
	
	protected ICAToken catoken = null;
	

	/** A workaround for the feature in SignServer 2.0 that property keys are 
	 * always converted to upper case. The EJBCA CA Tokens usually use mixed case properties
	 */
	protected Properties fixUpProperties(Properties props) {
		String prop = props.getProperty("AUTHCODE");
		if (prop != null) {
			props.setProperty("authCode", prop);
		}
		prop = props.getProperty("DEFAULTKEY");
		if (prop != null) {
			props.setProperty("defaultKey", prop);
		}
		prop = props.getProperty("PIN");
		if (prop != null) {
			props.setProperty("pin", prop);
		}
		prop = props.getProperty("SHAREDLIBRARY");
		if (prop != null) {
			props.setProperty("sharedLibrary", prop);
		}
		prop = props.getProperty("SLOT");
		if (prop != null) {
			props.setProperty("slot", prop);
		}
		prop = props.getProperty("SLOTLISTINDEX");
		if (prop != null) {
			props.setProperty("slotListIndex", prop);
		}
                prop = props.getProperty("ATTRIBUTESFILE");
		if (prop != null) {
			props.setProperty("attributesFile", prop);
		}
                prop = props.getProperty("NEXTCERTSIGNKEY");
		if (prop != null) {
			props.setProperty("nextCertSignKey", prop);
		}
		return props;
	}
	/**
	 * Method returning SignerStatus.STATUS_ACTIVE if every thing is OK, otherwise STATUS_OFFLINE.
	 * 
	 */
	public int getCryptoTokenStatus() {
        int status = catoken.getCATokenStatus();
        if(status == ICAToken.STATUS_ACTIVE){
        	return SignerStatus.STATUS_ACTIVE;
        }        		
		return SignerStatus.STATUS_OFFLINE;
	}

	/**
	 * Method activating the cryptographic token using the given key
	 * 
	 * @throws CryptoTokenAuthenticationFailureException if activation failed, message gives more info
	 * @throws CryptoTokenOfflineException if connection to token could not be created.
	 * 
	 */
	public void activate(String authenticationcode) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException {
		try {
			catoken.activate(authenticationcode);
		} catch (CATokenOfflineException e) {
			throw new CryptoTokenOfflineException(e.getMessage());
		} catch (CATokenAuthenticationFailedException e) {
			throw new CryptoTokenAuthenticationFailureException(e.getMessage());
		}
		
	}
	
	/**
	 * Method deactivating the cryptographic token
	 * 
	 * @return true if everything went successful
	 */
	public boolean deactivate() throws CryptoTokenOfflineException {
		boolean ret = false;
		try {
			ret = catoken.deactivate();
		} catch (Exception e) {
			throw new CryptoTokenOfflineException(e);
		}
		return ret;
	}
	
	/**
	 * Returns a reference to the private key to use.
	 * 
	 * @see org.signserver.server.cryptotokens.ICryptoToken 
	 */
	public PrivateKey getPrivateKey(int purpose) throws CryptoTokenOfflineException {
		try {
			return catoken.getPrivateKey(purpose);
		} catch (CATokenOfflineException e) {
			throw new CryptoTokenOfflineException(e.getMessage());
		}
	}

	/**
	 * Returns a reference to the public key to use.
	 * 
	 * @see org.signserver.server.cryptotokens.ICryptoToken 
	 */
	public PublicKey getPublicKey(int purpose) throws CryptoTokenOfflineException {
		try {
			return catoken.getPublicKey(purpose);
		} catch (CATokenOfflineException e) {
			throw new CryptoTokenOfflineException(e.getMessage());
		}	}

	/**
	 * Returns the provider name that should be used.
	 * @see ICryptoToken.PROVIDERUSAGE_SIGN
	 */
	public String getProvider(int providerUsage) {
       return catoken.getProvider();
	}

	public Certificate getCertificate(int purpose) throws CryptoTokenOfflineException {
		return null;
	}

	public Collection<Certificate> getCertificateChain(int purpose) throws CryptoTokenOfflineException {
		return null;
	}

	
	public ICertReqData genCertificateRequest(ISignerCertReqInfo info, final boolean defaultKey) throws CryptoTokenOfflineException {
		Base64SignerCertReqData retval = null;
		if(info instanceof PKCS10CertReqInfo){
			PKCS10CertReqInfo reqInfo = (PKCS10CertReqInfo) info; 
			PKCS10CertificationRequest pkcs10;
                        final int purpose = defaultKey
                                ? PURPOSE_SIGN : PURPOSE_NEXTKEY;
                        if (log.isDebugEnabled()) {
                            log.debug("Purpose: " + purpose);
                        }
			try {
				pkcs10 = new PKCS10CertificationRequest(reqInfo.getSignatureAlgorithm(),CertTools.stringToBcX509Name(reqInfo.getSubjectDN()),getPublicKey(purpose),reqInfo.getAttributes(),getPrivateKey(purpose),getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));
				retval = new Base64SignerCertReqData(Base64.encode(pkcs10.getEncoded()));
			} catch (InvalidKeyException e) {
				log.error(e);
			} catch (NoSuchAlgorithmException e) {
				log.error(e);
			} catch (NoSuchProviderException e) {
				log.error(e);
			} catch (SignatureException e) {
				log.error(e);
			}
						
		}
		return retval;
	}

	
	
	/**
	 * Method not supported
	 */
	public boolean destroyKey(int purpose) {		
		return false;
	}

        public Collection<KeyTestResult> testKey(String alias, char[] authCode)
                throws CryptoTokenOfflineException, KeyStoreException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        public static String createKeyHash(PublicKey key) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1", "BC");
            final String res = new String(
                    Hex.encode(md.digest(key.getEncoded())));
            md.reset();
            return res;
        } catch (NoSuchProviderException ex) {
            final String message
                    = "Nu such provider trying to hash public key";
            log.error(message, ex);
            throw new RuntimeException(message, ex);
        } catch (NoSuchAlgorithmException ex) {
            final String message
                    = "Nu such algorithm trying to hash public key";
            log.error(message, ex);
            throw new RuntimeException(message, ex);
        }
    }

    public static String suggestSigAlg(PublicKey key) {
        final String alg;
        if (key instanceof ECKey ) {
            alg = "SHA1withECDSA";
        } else if (key instanceof RSAKey ) {
            alg = "SHA1withRSA";
        } else if (key instanceof DSAKey ) {
            alg = "SHA1withDSA";
        } else {
            alg = null;
        }
        return alg;
    }
}
