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

import java.util.HashMap;

/**
 * Implementation of a services map.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ServicesImpl implements IServices {

    private final HashMap<Class<?>, Object> services = new HashMap<>();
    
    @Override
    public <T> T get(Class<? extends T> type) {
        return (T) services.get(type);
    }

    @Override
    public <T> T put(Class<? extends T> type, T service) {
        return (T) services.put(type, service);
    }
    
}
