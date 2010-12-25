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
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;

/**
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
     * @param context Various information such as transaction id etc.
     * @return True if the purchase was granted and performed
     * @throws AccounterException in case of error other than that the purchase
     * was not granted
     */
    boolean purchase(IClientCredential credential, ProcessRequest request,
            ProcessResponse response, RequestContext context)
                throws AccounterException;

}
