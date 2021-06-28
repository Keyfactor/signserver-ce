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
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.List;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.server.IServices;

/**
 * Delegator interface providing keystore operations needed by
 * CryptoTokenHelper to be implemented for different keystore implementations.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public interface KeyStoreDelegator {

    /**
     * Determine if a key alias is present in the keystore.
     * 
     * @param alias
     * @return true if alias exists in the keystore
     * @throws KeyStoreException 
     */
    public boolean containsAlias(String alias) throws KeyStoreException;

    /**
     * Delete entry from keystore.
     * 
     * @param alias of entry to delete
     * @throws KeyStoreException 
     */
    public void deleteEntry(String alias) throws KeyStoreException;

    /**
     * Get the public key associated with an alias.
     * 
     * @param keyAlias
     * @return Public key associated with alias
     * @throws KeyStoreException 
     */
    public PublicKey getPublicKey(String keyAlias) throws KeyStoreException;

    /**
     * Acquire exclusive use of a PrivateKey instance.
     *
     * Note: This must eventually follow be a call to releasePrivateKey().
     * 
     * @param alias of entry
     * @param password if one
     * @return the private key
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException 
     * @throws CryptoTokenOfflineException 
     */
    public PrivateKey aquirePrivateKey(String alias, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CryptoTokenOfflineException;

    /**
     * Call with a PrivateKey instance previously acquired in order to release it.
     *
     * @param privateKey to release
     */
    public void releasePrivateKey(PrivateKey privateKey);

    /**
     * Get token entries from the token.
     * 
     * @return List of token entries
     * @throws KeyStoreException 
     * @throws org.signserver.common.CryptoTokenOfflineException 
     */
    public List<TokenEntry> getEntries() throws KeyStoreException, CryptoTokenOfflineException;
    
    /**
     * Populate additional data for a token entry.
     * 
     * @param entry token entry to add additional data for
     * @param authCode password to the keystore/crypto token (if needed)
     * @param services
     * @throws KeyStoreException 
     * @throws org.signserver.common.CryptoTokenOfflineException 
     */
    void addAdditionalDataToEntry(TokenEntry entry, char[] authCode, IServices services)
            throws KeyStoreException, CryptoTokenOfflineException;

    /**
     * Assign a given key to a keystore entry.
     * 
     * @param alias of the keystore entry
     * @param key
     * @param authCode
     * @param certificate
     * @throws KeyStoreException 
     */
    public void setKeyEntry(String alias, PrivateKey key, char[] authCode, Certificate[] certificate)
            throws KeyStoreException;
}
