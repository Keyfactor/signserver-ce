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
package org.signserver.server.data.impl;

import java.util.Iterator;
import java.util.ServiceLoader;

/**
 * Utility methods for request/response data handling.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class DataUtils {
    
    /**
     * Create a new DataFactory implementation, either a service provided
     * implementation or the default one.
     * @return The new DataFactory instance
     */
    public static DataFactory createDataFactory() {
        final DataFactory result;
        Iterator<DataFactory> iterator = ServiceLoader.load(DataFactory.class).iterator();
        if (iterator.hasNext()) {
            result = iterator.next();
        } else {
            result = new DefaultDataFactory();
        }
        return result;
    }

}
