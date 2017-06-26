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
package org.signserver.test.utils.mock;

import org.signserver.common.RequestContext;
import org.signserver.server.IServices;

/**
 * Version of the RequestContext intended to be used by unit tests.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class MockedRequestContext extends RequestContext {

    /**
     * Creates a RequestContext and sets the services on it directly for 
     * convenience.
     * @param services 
     */
    public MockedRequestContext(final IServices services) {
        setServices(services);
    }
}
