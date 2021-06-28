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

import java.util.Properties;
import org.signserver.common.RequestContext;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;

/**
 * Interface for Accounters.
 * 
 * Accounters are responsible for charging a client for a successfully carried 
 * out worker request.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public interface IAccounter {

    /**
     * Method called after creation of instance.
     * @param props the signers properties
     */
    void init(Properties props);

    /**
     * Call this method to charge the client identified by credential for the
     * request/response given the supplied context.
     *
     * @param credential Credentials identifying the client
     * @param request The request the client made
     * @param response The response the worker put together
     * @param context Various information such as transaction id as well as 
     * runtime dependencies such as an EntityManager.
     * @return True if the purchase was granted and performed
     * @throws AccounterException in case of error other than that the purchase
     * was not granted
     */
    boolean purchase(IClientCredential credential, Request request,
            Response response, RequestContext context)
                throws AccounterException;

}
