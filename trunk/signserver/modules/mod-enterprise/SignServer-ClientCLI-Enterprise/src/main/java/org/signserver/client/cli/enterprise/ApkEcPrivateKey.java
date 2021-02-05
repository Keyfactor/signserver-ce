/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.client.cli.enterprise;

import java.util.Map;
import org.signserver.client.cli.defaultimpl.DocumentSignerFactory;

/**
 * Reference to an ECDSA private key for a remote ApkHashSigner.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ApkEcPrivateKey extends ApkPrivateKey {
    
    public ApkEcPrivateKey(final String workerName,
                           final DocumentSignerFactory signerFactory,
                           final Map<String, Object> requestContext,
                           final Map<String, String> metadata) {
        super(workerName, signerFactory, requestContext, metadata);
    }

    public ApkEcPrivateKey(final int workerId, 
                           final DocumentSignerFactory signerFactory,
                           final Map<String, Object> requestContext,
                           final Map<String, String> metadata) {
        super(workerId, signerFactory, requestContext, metadata);
    }

    @Override
    public String getAlgorithm() {
        return "EC";
    }    
}
