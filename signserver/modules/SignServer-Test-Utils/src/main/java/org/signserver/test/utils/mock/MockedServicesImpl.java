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

import org.signserver.server.ServicesImpl;

/**
 * Version of ServicesImpl intended to be used in the unit tests.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class MockedServicesImpl extends ServicesImpl {

    /**
     * Convenience method for putting a new implementation class.
     *
     * @param <T> type for the implementation
     * @param type class for the type
     * @param service the implementation
     * @return 
     */
    public <T> MockedServicesImpl with(Class<? extends T> type, T service) {
        super.put(type, service);
        return this;
    }
}
