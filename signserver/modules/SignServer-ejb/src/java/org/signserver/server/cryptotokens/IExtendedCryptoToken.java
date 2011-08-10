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

import java.io.Serializable;

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;

/**
 * Extended crypto token interface to support symmetric encryption
 * and key generation on the actual token.
 * 
 * Mostly used by Group Key Service implementations.
 * 
 * @author Philip Vendil 16 nov 2007
 * @version $Id$
 */
public interface IExtendedCryptoToken extends ICryptoToken {

    /**
     * Method instructing the crypto token to generate a key that is returned 
     * 
     * @param keyAlg the key algorithm to generate, it's up to the caller to check that the crypto token
     * used supports the given value.
     * @param keySpec specification of the key, it's up to the caller to check that the crypto token
     * used supports the given value.
     * @return either a java.security.Key or a java.security.KeyPair depending on type of keyAlg sent to the the crypto token.
     * @throws IllegalRequestException if the token doesn't support the given key alg or key spec.
     * @throws CryptoTokenOfflineException if the token isn't online.
     */
    Serializable genExportableKey(String keyAlg, String keySpec) throws IllegalRequestException, CryptoTokenOfflineException;

    /**
     * Instructs the crypto token to generate a key stored in the device returning only 
     * a alias reference to the key.
     * 
     * @param keyAlg the key algorithm to generate, it's up to the caller to check that the crypto token
     * @param keySpec keySpec specification of the key, it's up to the caller to check that the crypto token
     * used supports the given value.
     * @return a reference to the key in that can be used later for encryption/decryption.
     * 
     * @throws IllegalRequestException if the token doesn't support the given key alg or key spec.
     * @throws CryptoTokenOfflineException if the token isn't online.
     */
    String genNonExportableKey(String keyAlg, String keySpec) throws IllegalRequestException, CryptoTokenOfflineException;

    /**
     * Method used to encrypt data using a key stored in the crypto token. This
     * method should mainly be used for symmetric encryption.
     * @param keyRef a alias reference to the key that should be used.
     * @param data the data to encrypt.
     * @return the encrypted data.
     * @throws CryptoTokenOfflineException if the token isn't online.
     */
    byte[] encryptData(String keyRef, byte[] data) throws CryptoTokenOfflineException;

    /**
     * Method used to decrypt data using a key stored in the crypto token. This
     * method should mainly be used for symmetric encryption.
     * @param keyRef a alias reference to the key that should be used.
     * @param data the data to decrypt.
     * @return the encrypted data.
     * @throws CryptoTokenOfflineException if the token isn't online.
     */
    byte[] decryptData(String keyRef, byte[] data) throws CryptoTokenOfflineException;
}
