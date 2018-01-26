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

import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
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
     * Get an enumeration of available aliases in the keystore.
     * 
     * @return aliases
     * @throws KeyStoreException 
     */
    public Enumeration<String> aliases() throws KeyStoreException;

    /**
     * Determine if an entry is a key.
     * 
     * @param keyAlias
     * @return true if the alias is relating to a key
     * @throws KeyStoreException 
     */
    public boolean isKeyEntry(String keyAlias) throws KeyStoreException;

    /**
     * Get a certificate associated with an alias.
     * 
     * @param keyAlias
     * @return Certificate associated with alias
     * @throws KeyStoreException 
     */
    public Certificate getCertificate(String keyAlias) throws KeyStoreException;
    
    /**
     * Get key with a given alias.
     * 
     * @param alias
     * @param password
     * @return key
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException 
     */
    public Key getKey(String alias, char[] password)
        throws KeyStoreException, NoSuchAlgorithmException,
            UnrecoverableKeyException;
    
    /**
     * Get token entries from the token.
     * 
     * @return List of token entries
     * @throws KeyStoreException 
     */
    public List<TokenEntry> getEntries() throws KeyStoreException;

    /**
     * Get creation date of a keystore entry.
     * @param keyAlias of entry
     * @return The date the given entry was created
     * @throws KeyStoreException 
     */
    public Date getCreationDate(String keyAlias) throws KeyStoreException;

    /**
     * Get certificate chain associated with the given alias.
     * 
     * @param keyAlias
     * @return certificate chain
     * @throws KeyStoreException 
     */
    public Certificate[] getCertificateChain(String keyAlias) throws KeyStoreException;
    
    /**
     * Populate additional data for a token entry.
     * 
     * @param entry token entry to add additional data for
     * @param authCode password to the keystore/crypto token (if needed)
     * @param services
     * @throws KeyStoreException 
     */
    void addAdditionalDataToEntry(TokenEntry entry, char[] authCode, IServices services)
            throws KeyStoreException;

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
