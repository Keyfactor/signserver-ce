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
 
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Properties;

import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.server.KeyTestResult;


/** Interface maintaining devices performing cryptographic operations and handling the private key.
 *  All CryptoToken plug-ins must implement this interface.
 * 
 * @author Philip Vendil
 * @version $Id$
 */


public interface ICryptoToken {

	
	public static final int PURPOSE_SIGN = 1;
	public static final int PURPOSE_DECRYPT = 2;
	
        /** 
         * Indicating the next key. Property: "nextCertSignKey".
         * @see org.ejbca.core.model.SecConst#CAKEYPURPOSE_CERTSIGN_NEXT
         */
        int PURPOSE_NEXTKEY = 7;
	
	public static final int PROVIDERUSAGE_SIGN    = 1;
	public static final int PROVIDERUSAGE_DECRYPT = 2;

        String ALL_KEYS = "all";
	
   /** 
    * Method called after creation of instance.
    *
    */	
	public abstract void init(int workerId, Properties props) throws CryptoTokenInitializationFailureException;
	
	/**
	 *  Method that returns the current status of the crypto token.
	 * 
	 *  Should return one of the SignerStatus.STATUS_.. values 
	 */
	public abstract int getCryptoTokenStatus();
	
    /**
     * Method used to activate SignTokens when connected after being off-line.
     * 
     * @param authenticationcode used to unlock crypto token, i.e PIN for smartcard HSMs
     * @throws CryptoTokenOfflineException if SignToken is not available or connected.
     * @throws CryptoTokenAuthenticationFailureException with error message if authentication to crypto token fail.
     */
    public abstract void activate(String authenticationcode) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException;    

    /**
     * Method used to deactivate crypto tokens. 
     * Used to set a crypto token too off-line status and to reset the HSMs authorization code.
     * 
     * @return true if deactivation was successful.
     */
    public abstract boolean deactivate() throws CryptoTokenOfflineException;    
    
    /** Returns the private key (if possible) of token.
    *
    * @param purpose should one of the PURPOSE_... constants 
    * @throws CryptoTokenOfflineException if CryptoToken is not available or connected.
    * @return PrivateKey object
    */
    public abstract PrivateKey getPrivateKey(int purpose) throws CryptoTokenOfflineException;

    /** Returns the public key (if possible) of token.
    *
    * @param purpose should one of the PURPOSE_... constants    
    * @throws CryptoTokenOfflineException if CryptoToken is not available or connected.
    * @return PublicKey object
    */
    public abstract PublicKey getPublicKey(int purpose) throws CryptoTokenOfflineException;
    
    
    /** Returns the signature Provider that should be used to sign things with
     *  the PrivateKey object returned by this crypto device implementation.
     *  @param providerUsage should be one if the ICryptoToken.PROVIDERUSAGE_ constants
     *  specifying the usage of the private key. 
     * @return String the name of the Provider
     */
    public abstract String getProvider(int providerUsage);
    
    /**
     * Method returning the crypto tokens certificate if it's included in the token.
     * This method should only be implemented by soft crypto tokens which have the certificate
     * included in the key store.
     * 
     * All other crypto tokens should return 'null' and let the signer fetch the certificate from database.
     * 
     */
    
    public abstract Certificate getCertificate(int purpose) throws CryptoTokenOfflineException;
    
    
    /**
     * Method returning the crypto tokens certificate chain if it's included in the token.
     * This method should only be implemented by soft crypto tokens which have the certificates
     * included in the key store.
     * 
     * All other crypto tokens should return 'null' and let the signer fetch the certificate from database.
     * 
     */
    
    public abstract Collection<Certificate> getCertificateChain(int purpose) throws CryptoTokenOfflineException;
    
	/**
	 * Method used to tell the crypto token to create a certificate request using its crypto token.
	 */
	public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean defaultKey) throws CryptoTokenOfflineException;
	
	/**
	 * Method used to remove a key in the signer that shouldn't be used any more
	 * @param purpose on of ICryptoToken.PURPOSE_ constants
	 * @return true if removal was successful.
	 */
	public boolean destroyKey(int purpose);


    /**
     * Tests the key identified by alias or all key if "all" specified.
     *
     * @param alias Name of key to test or "all" to test all available
     * @param authCode Authorization code
     * @return Collection with test results for each key
     * @throws CryptoTokenOfflineException
     * @throws KeyStoreException
     */
    public Collection<KeyTestResult> testKey(String alias,
            char[] authCode)
            throws CryptoTokenOfflineException, KeyStoreException;
}
