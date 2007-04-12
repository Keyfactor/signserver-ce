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

package org.signserver.server.signtokens;
 
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Properties;

import org.signserver.common.ISignerCertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.SignTokenAuthenticationFailureException;
import org.signserver.common.SignTokenOfflineException;


/** Interface maintaining devices producing signatures and handling the private key.
 *  All SignToken plug-ins must implement this interface.
 * 
 * @author Philip Vendil
 * @version $Id: ISignToken.java,v 1.3 2007-04-12 04:01:10 herrvendil Exp $
 */


public interface ISignToken {

	
	public static final int PURPOSE_SIGN = 1;
	
	public static final int PROVIDERUSAGE_SIGN    = 1;
	public static final int PROVIDERUSAGE_DECRYPT = 2;
	
   /** 
    * Method called after creation of instance.
    *
    */	
	public abstract void init(Properties props);
	
	/**
	 *  Method that returns the current status of the signtoken.
	 * 
	 *  Should return one of the SignerStatus..STATUS_.. values 
	 */
	public abstract int getSignTokenStatus();
	
    /**
     * Method used to activate SignTokens when connected after being offline.
     * 
     * @param authenticationcode used to unlock catoken, i.e PIN for smartcard HSMs
     * @throws SignTokenOfflineException if SignToken is not available or connected.
     * @throws SignTokenAuthenticationFailedException with error message if authentication to SignTokens fail.
     */
    public abstract void activate(String authenticationcode) throws SignTokenAuthenticationFailureException, SignTokenOfflineException;    

    /**
     * Method used to deactivate HardCATokens. 
     * Used to set a CAToken too offline status and to reset the HSMs authorization code.
     * 
     * @return true if deactivation was successful.
     */
    public abstract boolean deactivate();    
    
    /** Returns the private key (if possible) of token.
    *
    * @param purpose should one of the PURPOSE_... constants 
    * @throws SignTokenOfflineException if SignToken is not available or connected.
    * @return PrivateKey object
    */
    public abstract PrivateKey getPrivateKey(int purpose) throws SignTokenOfflineException;

    /** Returns the public key (if possible) of token.
    *
    * @param purpose should one of the PURPOSE_... constants    
    * @throws SignTokenOfflineException if SignToken is not available or connected.
    * @return PublicKey object
    */
    public abstract PublicKey getPublicKey(int purpose) throws SignTokenOfflineException;
    
    
    /** Returns the signature Provider that should be used to sign things with
     *  the PrivateKey object returned by this signingdevice implementation.
     *  @param providerUsage should be one if the ISignToken.PROVIDERUSAGE_ constants
     *  specifying the usage of the privatekey. 
     * @return String the name of the Provider
     */
    public abstract String getProvider(int providerUsage);
    
    /**
     * Method returning the signertokens certificate if it's included in the token.
     * This method should only be implemented by soft signtokens which have the certificate
     * included in the keystore.
     * 
     * All other signtokens should return 'null' and let the signer fetch the certificate from database.
     * 
     */
    
    public abstract Certificate getCertificate(int purpose) throws SignTokenOfflineException;
    
    
    /**
     * Method returning the signertokens certificatechain if it's included in the token.
     * This method should only be implemented by soft signtokens which have the certificates
     * included in the keystore.
     * 
     * All other signtokens should return 'null' and let the signer fetch the certificate from database.
     * 
     */
    
    public abstract Collection getCertificateChain(int purpose) throws SignTokenOfflineException;
    
	/**
	 * Method used to tell the signer to create a certificate request using its sign token.
	 */
	public ISignerCertReqData genCertificateRequest(ISignerCertReqInfo info) throws SignTokenOfflineException;
	
	/**
	 * Method used to remove a key in the signer that shouldn't be used any more
	 * @param purpose on of ISignToken.PURPOSE_ constants
	 * @return true if removal was successfull.
	 */
	public boolean destroyKey(int purpose);
}
