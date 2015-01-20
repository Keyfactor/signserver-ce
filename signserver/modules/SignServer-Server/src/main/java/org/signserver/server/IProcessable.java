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

import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;
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
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.cryptotokens.IKeyGenerator;

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
            throws CryptoTokenOfflineException;

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
            throws CryptoTokenOfflineException;
    
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
            char[] authCode) throws CryptoTokenOfflineException,
                IllegalArgumentException;

    /**
     * @see ICryptoToken#testKey(java.lang.String, char[])
     */
    public Collection<KeyTestResult> testKey(String alias,
            char[] authCode)
            throws CryptoTokenOfflineException, KeyStoreException;
 
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
     * @throws CryptoTokenOfflineException
     * @throws IllegalArgumentException 
     */
    void importCertificateChain(List<Certificate> certChain, String alias)
            throws CryptoTokenOfflineException, IllegalArgumentException;
}
