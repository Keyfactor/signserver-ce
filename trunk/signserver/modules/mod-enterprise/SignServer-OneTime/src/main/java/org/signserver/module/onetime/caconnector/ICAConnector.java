/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.onetime.caconnector;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.IServices;
import org.signserver.server.SignServerContext;
import org.signserver.server.cryptotokens.ICryptoTokenV4;

/**
 * The CA connector offers certificate issuance, possibly by sending a request
 * to a CA.
 *
 * @author Markus Kilås
 * @version $Id: ICAConnector.java 9470 2018-08-07 09:59:52Z vinays $
 */
public interface ICAConnector {
    
    /**
     * Initializes this instance.
     * @param config worker configuration containing the CA connector properties
     * @param context the SignServer context that can be used when initializing
     * this instance
     */
    void init(WorkerConfig config, SignServerContext context);
    
    /**
     * Constructs and returns a list of configuration and runtime errors that
     * would prevent this CA connector from being functional.
     * @param cryptoToken backing crypto token
     * @param services implementations to use
     * @return A list of errors, or empty if there's no fatal errors
     */
    List<String> getFatalErrors(ICryptoTokenV4 cryptoToken, IServices services);
    
    /**
     * Request a certificate from the CA.
     * 
     * @param cryptoToken backing crypto token
     * @param name User name
     * @param privateKey Private key
     * @param publicKey Public key
     * @param provider Provider name to use
     * @param requestContext SignServer request context
     * @return CAResponse
     * @throws CAException 
     */
    CAResponse requestCertificate(ICryptoTokenV4 cryptoToken, String name, PrivateKey privateKey, PublicKey publicKey, String provider, RequestContext requestContext) throws CAException;
    
}
