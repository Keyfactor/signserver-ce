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
package org.signserver.server.aliasselectors;

import java.util.List;
import javax.persistence.EntityManager;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.IProcessable;
import org.signserver.server.WorkerContext;
import org.signserver.common.data.Request;

/**
 * Key alias selector interface.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public interface AliasSelector {
    
    /**
     * Initialize the alias selector.
     * 
     * @param workerId Worker ID
     * @param config Worker configuration
     * @param workerContext Worker context
     * @param workerEM Entity manager
     */
    void init(final int workerId, final WorkerConfig config,
              final WorkerContext workerContext, final EntityManager workerEM);

    /**
     * Get a key alias for a given process request (i.e. sign request).
     * If the signRequest and requestContext parameters are null, an implementation
     * of this interface can choose to i.e. return a default alias to be used
     * outside of a signing request or to return null to indicate that no alias
     * has been selected.
     * 
     * @param purpose Key purpose
     * @param processble The processable instance handling the request
     * @param signRequest The request
     * @param requestContext The request context
     * @return The key alias given by the selector for the request data,
     *         or null if no suitable alias was found
     * @throws IllegalRequestException
     * @throws CryptoTokenOfflineException
     * @throws SignServerException 
     */
    String getAlias(final int purpose, final IProcessable processble, final Request signRequest,
                    final RequestContext requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
                   SignServerException;
    
    /**
     * Get fatal configuration errors for the alias selector.
     * 
     * @return List of error strings, or an empty list if there is no errors.
     */
    List<String> getFatalErrors();
}
