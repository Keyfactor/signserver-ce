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

import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.NoSuchAliasException;
import org.signserver.common.DuplicateAliasException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.QueryException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.TokenOutOfSpaceException;
import org.signserver.server.IServices;

/**
 * Forth version of the crypto token interface.
 *
 * Merging: V2, V3, KeyGenerator and KeyRemover
 * 
 * @author Marcus Lundblad
 * @author Markus Kilås
 * @version $Id$
 */
public interface ICryptoTokenV4 {
    
    int PURPOSE_SIGN = 1;
    
    int PURPOSE_DECRYPT = 2;
    
    /** 
     * Indicating the next key. Property: "nextCertSignKey".
     * @see org.ejbca.core.model.SecConst#CAKEYPURPOSE_CERTSIGN_NEXT
     */
    int PURPOSE_NEXTKEY = 7;
    
    int PROVIDERUSAGE_SIGN = 1;
    
    int PROVIDERUSAGE_DECRYPT = 2;
    
    /** Crypto token parameter with value of type Boolean telling if the crypto instance should be cached or not. */
    String PARAM_CACHEPRIVATEKEY = "CACHEPRIVATEKEY";
    
    /** Crypto token parameter with the value of type Map&lt;String, Object&gt; containing a cache local to this worker instance but possible shared among multiple threads. */
    String PARAM_WORKERCACHE = "WORKERCACHE";
    
    String ALL_KEYS = "all";
    
    String PARAM_INCLUDE_DUMMYCERTIFICATE = "INCLUDE_DUMMYCERTIFICATE";

    void init(int workerId, Properties props, IServices services) throws CryptoTokenInitializationFailureException;

    /**
     * Method used to activate SignTokens when connected after being off-line.
     * 
     * @param authenticationcode used to unlock crypto token, i.e PIN for smartcard HSMs
     * @param services services for implementations to use
     * @throws CryptoTokenOfflineException if SignToken is not available or connected.
     * @throws CryptoTokenAuthenticationFailureException with error message if authentication to crypto token fail.
     */
    void activate(String authenticationcode, IServices services) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException;

    /**
     * Method used to deactivate crypto tokens. 
     * Used to set a crypto token too off-line status and to reset the HSMs authorization code.
     * 
     * @param services services for implementations to use
     * @return true if deactivation was successful.
     * @throws CryptoTokenOfflineException
     */
    boolean deactivate(IServices services) throws CryptoTokenOfflineException;

    /** Returns the signature Provider that should be used to sign things with
     *  the PrivateKey object returned by this crypto device implementation.
     *  @param providerUsage should be one if the ICryptoTokenV4.PROVIDERUSAGE_ constants
     *  specifying the usage of the private key. 
     * @return String the name of the Provider
     */
    //TODO: Maybe not: String getProvider(int providerUsage);


    /**
     * @return The underlaying KeyStore (if any).
     * @throws UnsupportedOperationException If this implementation does not
     *  support KeyStore.
     * @throws CryptoTokenOfflineException
     * @throws KeyStoreException
     */
    //TODO: Maybe not?
    KeyStore getKeyStore() throws UnsupportedOperationException,
            CryptoTokenOfflineException, KeyStoreException;

    /**
     * Get token status.
     * 
     * @param services Services for implementations to use
     * @return The current state of the crypto token
     */
    int getCryptoTokenStatus(IServices services);
    
    /**
     * Import certificate chain to a crypto token.
     * 
     * @param certChain Certificate chain to import, should contain signing certificate
     * @param alias Key alias to import certificate chain in
     * @param athenticationCode Alias-specific authentication code. If this is null
     *                          uses the token's authentication code (set when activating)
     * @param params Additional parameters to pass to the crypto token
     * @param services implementations for the crypto token to use
     * @throws TokenOutOfSpaceException in case the certificate can not be imported because of space issues
     * @throws CryptoTokenOfflineException In case the token was not active or could not function for any other reasons
     * @throws InvalidAlgorithmParameterException If the supplied crypto token parameters was not valid
     * @throws NoSuchAliasException In case the alias did not exist in the token
     * @throws UnsupportedCryptoTokenParameter In case the supplied crypto token parameter was not known or supported by the token
     */
    void importCertificateChain(List<Certificate> certChain, String alias,
            char[] athenticationCode, Map<String, Object> params,
            IServices services) throws 
            TokenOutOfSpaceException,
            CryptoTokenOfflineException,
            NoSuchAliasException,
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter;
    
    /**
     * Queries the entries in the token.
     * @param startIndex Start index of first result (0-based)
     * @param max Maximum number of results to return
     * @param qc Search criteria for matching results
     * @param includeData If 'false' only the alias and key type is included, otherwise all information available is returned
     * @param params Additional crypto token parameters to pass to the token
     * @param services Implementations for the token to use
     * @return The search result
     * @throws CryptoTokenOfflineException In case the token was not active or could not function for any other reasons
     * @throws QueryException In case the query could not be understood or could not be executed
     * @throws InvalidAlgorithmParameterException If the supplied crypto token parameters was not valid
     * @throws UnsupportedCryptoTokenParameter In case the supplied crypto token parameter was not known or supported by the token
     */
    TokenSearchResults searchTokenEntries(int startIndex, int max, QueryCriteria qc, boolean includeData, Map<String, Object> params, IServices services) throws
            CryptoTokenOfflineException,
            QueryException,
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter;
    
    /**
     * Acquire a crypto instance in order to perform crypto operations during
     * a limited scope.
     * 
     * It is the caller's responsibility to make sure the call is followed up
     * by a call to releaseCryptoInstance() for each instance. Use try-final.
     * 
     * @param alias of the entry in the CryptoToken to quire an crypto instance for
     * @param params Additional parameters to pass to the crypto token
     * @param context the request context
     * @return an crypto instance
     * @throws CryptoTokenOfflineException In case the token was not active or could not function for any other reasons
     * @throws NoSuchAliasException In case the alias doesn't exist
     * @throws InvalidAlgorithmParameterException In case an algorithm is not supported by the token implementation
     * @throws UnsupportedCryptoTokenParameter In case a parameter is not supported by the token implementation
     * @throws IllegalRequestException If the operation could not be carried out because an issue with the request
     * @throws SignServerException For other internal (not to be leaked to the client side) errors
     */
    ICryptoInstance acquireCryptoInstance(String alias, Map<String, Object> params, RequestContext context) throws
            CryptoTokenOfflineException, 
            NoSuchAliasException, 
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            IllegalRequestException, 
            SignServerException;

    /**
     * Releases a previously acquired crypto instance.
     * @param instance to release
     * @param context the request context
     */
    void releaseCryptoInstance(ICryptoInstance instance, RequestContext context);

    /**
     * @throws CryptoTokenOfflineException In case the token was not active or could not function for any other reasons
     * @throws IllegalArgumentException
     */
    
    
    /**
     * Generate a new key.
     * @param keyAlgorithm Key algorithm
     * @param keySpec Key specification
     * @param alias Name of the new key
     * @param authCode Authorization code for the key
     * @param params Additional parameters to pass to the crypto token
     * @param services Implementations for the crypto token to use
     * @throws TokenOutOfSpaceException in case the key can not be generate because of space issues
     * @throws CryptoTokenOfflineException In case the token was not active or could not function for any other reasons
     * @throws DuplicateAliasException In case the alias did already exist
     * @throws NoSuchAlgorithmException If the key algorithm was not understood
     * @throws InvalidAlgorithmParameterException If the key spec or the crypto token parameters was not correct
     * @throws UnsupportedCryptoTokenParameter If one or more crypto token parameters was unknown or not supported by the token implementation
     */
    void generateKey(String keyAlgorithm, String keySpec, String alias,
            char[] authCode, Map<String, Object> params, IServices services) throws
            TokenOutOfSpaceException,
            CryptoTokenOfflineException,
            DuplicateAliasException, 
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter;

    /**
     * Generate a certificate signing request.
     * @param info CSR information
     * @param explicitEccParameters True if explicit ECC parameters should be included
     * @param keyAlias Alias of key to generate the request for/using
     * @param services Implementations for the crypto token to use
     * @return the request
     * @throws CryptoTokenOfflineException In case the token was not active or could not function for any other reasons
     * @throws NoSuchAliasException In case the alias did not exist in the token
     */
    ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            boolean explicitEccParameters, String keyAlias, IServices services)
            throws
            CryptoTokenOfflineException,
            NoSuchAliasException;

    /**
     * Tests the key identified by alias or all key if "all" specified.
     * @param alias Name of key to test or "all" to test all available
     * @param authCode Authorization code for the key/keys to test, if needed
     * @param Services Implementations for the crypto token to use
     * @return Collection with test results, one for each key
     * @throws CryptoTokenOfflineException In case the token was not active or could not function for any other reasons
     * @throws KeyStoreException In case of error accessing the key
     */
    Collection<KeyTestResult> testKey(String alias,
            char[] authCode,
            IServices Services)
            throws CryptoTokenOfflineException, KeyStoreException;
    
    /**
     * Remove a key from the token (if supported).
     *
     * @param alias of key to remove
     * @param services services for the implementations to use
     * @return True if the key was successfully removed or false it failed or the token does not support key removal
     * @throws CryptoTokenOfflineException if the token was not activated
     * @throws KeyStoreException for keystore related errors
     * @throws SignServerException if the keystore did not contain a key with the specified alias
     */
    boolean removeKey(String alias, IServices services) throws CryptoTokenOfflineException, 
            KeyStoreException, SignServerException;
    
    /**
     * If signer requires no certificates when using this crypto token.
     *
     * @return True or false
     */
    boolean isNoCertificatesRequired();
}
