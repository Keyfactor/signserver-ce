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

import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.List;
import javax.crypto.SecretKey;

/**
 * Represents an instance in the CryptoToken that can be used to access
 * a PrivateKey for signing or a secret key for symmetric crypto operations.
 * 
 * The instance can be obtained from an ICryptoTokenV4 and should be released
 * as soon as it will not be used anymore.
 * 
 * @author Markus Kilås
 * @version $Id$
 * @see ICryptoTokenV4
 */
public interface ICryptoInstance /** Java7: extends AutoClosable */ {

    /**
     * @return The certificate (or null for secret keys)
     */
    Certificate getCertificate();
    
    /**
     * @return Get the certificate chain (or null for secret keys)
     */
    List<Certificate> getCertificateChain();
    
    /**
     * @return Get private key (or null for secret keys)
     */
    PrivateKey getPrivateKey();
    
    /**
     * @return Get the public key (if any, null for secret keys)
     */
    PublicKey getPublicKey();
    
    /**
     * @return Get the secret key (or null for asymmetric key)
     */
    SecretKey getSecretKey();
    
    /**
     * @return Get the keystore provider
     */
    Provider getProvider();
}
