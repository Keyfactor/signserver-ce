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

import java.security.PrivateKey;
import java.util.Map;
import org.signserver.client.cli.defaultimpl.DocumentSignerFactory;

/**
 * Private key reference for use with the APK client-side file-specific
 * handler. References an ApkHashSigner server-side signer performing the
 * actual crypto operation.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public abstract class ApkPrivateKey implements PrivateKey {

    private int workerId;
    private String workerName;
    private final DocumentSignerFactory signerFactory;
    private final Map<String, Object> requestContext;
    private final Map<String, String> metadata;

    /**
     * Construct a key reference referring to a signer by name.
     *
     * @param workerName 
     * @param signerFactory 
     * @param requestContext 
     */
    public ApkPrivateKey(final String workerName,
                         final DocumentSignerFactory signerFactory,
                         final Map<String, Object> requestContext,
                         final Map<String, String> metadata) {
        this.workerName = workerName;
        this.signerFactory = signerFactory;
        this.requestContext = requestContext;
        this.metadata = metadata;
    }

    /**
     * Construct a key reference referrring to a signer by ID.
     *
     * @param workerId 
     * @param signerFactory 
     * @param requestContext 
     */
    public ApkPrivateKey(final int workerId,
                         final DocumentSignerFactory signerFactory,
                         final Map<String, Object> requestContext,
                         final Map<String, String> metadata) {
        this.workerId = workerId;
        this.signerFactory = signerFactory;
        this.requestContext = requestContext;
        this.metadata = metadata;
    }

    /**
     * The worker name referenced by the key.
     *
     * @return The worker name, or null if the key referres an ID
     */
    public String getWorkerName() {
        return workerName;
    }

    /**
     * The worker ID referrenced by the key.
     *
     * @return The worker ID (0 if referenced by worker name instead)
     */
    public int getWorkerId() {
        return workerId;
    }

    /**
     * The signer factory to create concreate signer instance for the invocation.
     * 
     * @return A signer factory instance
     */
    public DocumentSignerFactory getSignerFactory() {
        return signerFactory;
    }

    /**
     * The request context assoiated by the request connected to the handle.
     *
     * @return A request context
     */
    public Map<String, Object> getRequestContext() {
        return requestContext;
    }

    /**
     * Request metadata to include in the request.
     *
     * @return 
     */
    public Map<String, String> getMetadata() {
        return metadata;
    }

    @Override
    public String getFormat() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}
