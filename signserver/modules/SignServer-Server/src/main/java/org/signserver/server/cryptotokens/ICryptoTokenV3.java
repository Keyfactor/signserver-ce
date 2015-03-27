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
import org.signserver.server.IServices;

/**
 * Third version of the crypto token interface.
 * Adding support for:
 * - importing certificates to crypto tokens
 * - search for entries in the crypto token
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public interface ICryptoTokenV3 extends ICryptoTokenV2 {

    // TODO: Add IServices to old methods from V2
    
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
     * @throws CryptoTokenOfflineException
     * @throws IllegalArgumentException
     */
    void importCertificateChain(List<Certificate> certChain, String alias,
            char[] athenticationCode, Map<String, Object> params, IServices services)
            throws CryptoTokenOfflineException, IllegalArgumentException;
    
    TokenSearchResults searchTokenEntries(final int startIndex, final int max, final QueryCriteria qc, final boolean includeData, Map<String, Object> params, IServices services) 
            throws CryptoTokenOfflineException, QueryException;
    
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
     * @throws CryptoTokenOfflineException
     * @throws IllegalRequestException
     * @throws SignServerException 
     */
    ICryptoInstance acquireCryptoInstance(String alias, Map<String, Object> params, RequestContext context) throws CryptoTokenOfflineException, IllegalRequestException, SignServerException;
    
    /**
     * Releases a previously acquired crypto instance.
     * @param instance to release
     * @param context the request context
     */
    void releaseCryptoInstance(ICryptoInstance instance, RequestContext context);

    /**
     * Generate a new keypair.
     * @param keyAlgorithm Key algorithm
     * @param keySpec Key specification
     * @param alias Name of the new key
     * @param authCode Authorization code
     * @param params Additional parameters to pass to the crypto token
     * @param services implementations for the crypto token to use
     * @throws CryptoTokenOfflineException
     * @throws IllegalArgumentException
     */
    void generateKey(String keyAlgorithm, String keySpec, String alias,
            char[] authCode, Map<String, Object> params, IServices services) throws CryptoTokenOfflineException,
                IllegalArgumentException;

    ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            boolean explicitEccParameters, String keyAlias, IServices services)
            throws CryptoTokenOfflineException;
    
    Collection<KeyTestResult> testKey(String alias,
            char[] authCode,
            IServices Services)
            throws CryptoTokenOfflineException, KeyStoreException;
}
