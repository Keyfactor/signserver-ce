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
package org.signserver.server;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.QueryException;
import org.signserver.common.WorkerStatus;
import org.signserver.common.DuplicateAliasException;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.cryptotokens.ICryptoTokenV3;
import org.signserver.server.cryptotokens.IKeyGenerator;
import org.signserver.common.NoSuchAliasException;
import org.signserver.server.cryptotokens.TokenSearchResults;
import org.signserver.common.UnsupportedCryptoTokenParameter;

/**
 * IProcessable is an interface that all processable workers should implement.
 * 
 * There exists a BaseTimedService that can be extended covering some of it's 
 * functions.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public interface IProcessable extends IWorker {

    String AUTHTYPE_CLIENTCERT  = "CLIENTCERT";
    String AUTHTYPE_NOAUTH      = "NOAUTH";

    /**
     * Main method that does the actual signing according to the data in the request.
     *
     *  @throws IllegalRequestException if requests contain unsupported data.
     *  @throws CryptoTokenOfflineException if the token performing cryptographic operations is off-line.
     *  @throws SignServerException if general failure occurred during the operation.
     */
    ProcessResponse processData(ProcessRequest signRequest,
            RequestContext requestContext) throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException;

    /**
     * Method used to activate a processable worker using the supplied authentication Code
     *
     * Optional method, if not supported throw a CryptoTokenOfflineException
     *
     * @param authCode
     */
    void activateSigner(String authCode) throws
            CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException;

    /**
     * Method used to deactivate a processable worker when it's not used anymore
     *
     * Optional method, if not supported throw a CryptoTokenOfflineException
     */
    boolean deactivateSigner() throws CryptoTokenOfflineException;

    /**
     * Method used to tell the processable worker to create a certificate request using its crypto token.
     *
     * Optional method, if not supported throw a CryptoTokenOfflineException
     */
    ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            boolean explicitEccParameters, boolean defaultKey)
            throws CryptoTokenOfflineException, NoSuchAliasException;

    /**
     * Generate a certificate request using the worker's crypto token, given
     * a key alias.
     * 
     * @param info Certificate request info
     * @param explicitEccParameters If explicit ECC parameters should be used
     * @param keyAlias Key alias in crypto token
     * @return Certificate request data
     * @throws CryptoTokenOfflineException 
     */
    ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            boolean explicitEccParameters, String keyAlias)
            throws CryptoTokenOfflineException, NoSuchAliasException;

    ICertReqData genCertificateRequest(ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, String keyAlias, IServices services) throws CryptoTokenOfflineException, NoSuchAliasException;

    ICertReqData genCertificateRequest(ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, boolean defaultKey, IServices services) throws CryptoTokenOfflineException, NoSuchAliasException;
        
    /**
     * Method specifying which type of authentication that should be performed before signature is performed
     * Returns one of the AUTHTYPE_ constants
     */
    String getAuthenticationType();

    /**
     * Method used to remove a key in the processable worker that shouldn't be used any more
     *
     * Optional method, if not supported return false.
     *
     * @param purpose on of ICryptoToken.PURPOSE_ constants
     * @return true if removal was successful.
     */
    boolean destroyKey(int purpose);

    /**
     * @see IKeyGenerator#generateKey(java.lang.String, java.lang.String,
     *  java.lang.String, char[])
     */
    void generateKey(String keyAlgorithm, String keySpec, String alias,
            char[] authCode) throws
            CryptoTokenOfflineException,
            DuplicateAliasException, 
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter;;

    /**
     * @see ICryptoTokenV3#generateKey(java.lang.String, java.lang.String, java.lang.String, char[], java.util.Map, org.signserver.server.IServices) 
     */
    void generateKey(final String keyAlgorithm, final String keySpec, final String alias, final char[] authCode, Map<String, Object> params, final IServices services) throws
            CryptoTokenOfflineException,
            DuplicateAliasException, 
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter;
    
    /**
     * @see ICryptoToken#testKey(java.lang.String, char[])
     */
    Collection<KeyTestResult> testKey(String alias,
            char[] authCode)
            throws CryptoTokenOfflineException, KeyStoreException;

    /**
     * @see ICryptoTokenV3#testKey(java.lang.String, char[], org.signserver.server.IServices) 
     */
    Collection<org.signserver.common.KeyTestResult> testKey(String alias,
        char[] authCode, IServices services) throws CryptoTokenOfflineException, KeyStoreException;
 
    /**
     * @return The status of the crypto token
     * @see WorkerStatus#STATUS_ACTIVE
     * @see WorkerStatus#STATUS_OFFLINE
     */
    int getCryptoTokenStatus();
    
    /**
     * Import a signing certificate chain to the signer's crypto token.
     * 
     * @param certChain Certificate chain to import 
     * @param alias Alias to use in the crypto token
     * @param authenticationCode Authentication code for the key entry, or use
     *                           the token's authentication code if null
     * @throws CryptoTokenOfflineException In case the token was not active or could not function for any other reasons
     * @throws NoSuchAliasException In case the alias did not exist in the token
     * @throws InvalidAlgorithmParameterException If the supplied crypto token parameters was not valid
     * @throws OperationUnsupportedException in case the import operation is not supported by the worker
     * @throws UnsupportedCryptoTokenParameter In case the supplied crypto token parameter was not known or supported by the token
     */
    void importCertificateChain(List<Certificate> certChain, String alias, char[] authenticationCode, Map<String, Object> params, IServices services) throws
            CryptoTokenOfflineException,
            NoSuchAliasException,
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            OperationUnsupportedException;

    /**
     * Queries the worker's crypto token.
     *
     * @param startIndex Start index of first result (0-based)
     * @param max Maximum number of results to return
     * @param qc Search criteria for matching results
     * @param includeData If 'false' only the alias and key type is included, otherwise all information available is returned
     * @param params Additional parameters to pass to the crypto token
     * @param services implementations for the crypto token to use
     * @return the search result
     * @throws OperationUnsupportedException in case the search operation is not supported by the worker
     * @throws CryptoTokenOfflineException in case the token is not in a searchable state
     * @throws InvalidAlgorithmParameterException If the supplied crypto token parameters was not valid
     * @throws UnsupportedCryptoTokenParameter In case the supplied crypto token parameter was not known or supported by the token
     * @throws QueryException in case the query could not be understood or could not be executed
     */
    TokenSearchResults searchTokenEntries(int startIndex, int max, final QueryCriteria qc, final boolean includeData, Map<String, Object> params, final IServices services) throws
            CryptoTokenOfflineException,
            QueryException,
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            OperationUnsupportedException;
}
