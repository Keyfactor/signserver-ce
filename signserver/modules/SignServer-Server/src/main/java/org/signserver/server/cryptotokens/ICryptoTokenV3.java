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
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.cesecore.util.query.QueryCriteria;
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
 * Third version of the crypto token interface.
 *
 * Adding support for:
 * - importing certificates to crypto tokens
 * - search for entries in the crypto token
 * - getting access to a crypto token during a limited scope
 * 
 * @author Marcus Lundblad
 * @author Markus Kilås
 * @version $Id$
 */
public interface ICryptoTokenV3 extends ICryptoTokenV2 {
    
    /** Crypto token parameter with value of type Boolean telling if the crypto instance should be cached or not. */
    String PARAM_CACHEPRIVATEKEY = "CACHEPRIVATEKEY";
    
    /** Crypto token parameter with the value of type Map&lt;String, Object&gt; containing a cache local to this worker instance but possible shared among multiple threads. */
    String PARAM_WORKERCACHE = "WORKERCACHE";
    
    /**
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
     * @throws IllegalRequestException If the operation could not be carried out because an issue with the request
     * @throws SignServerException If the request could not be carried out for any other reasons
     */
    ICryptoInstance acquireCryptoInstance(String alias, Map<String, Object> params, RequestContext context) throws
            CryptoTokenOfflineException, 
            NoSuchAliasException, 
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            IllegalRequestException;

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
}
