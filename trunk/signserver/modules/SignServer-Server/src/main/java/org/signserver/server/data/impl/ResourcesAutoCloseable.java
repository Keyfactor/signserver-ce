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

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import org.apache.log4j.Logger;

/**
 * Abstract AutoCloseable providing a method register(Closeable) that can be
 * used by subclasses to have resources properly closed.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class ResourcesAutoCloseable implements AutoCloseable {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CloseableReadableData.class);
    
    private final ArrayList<Closeable> resources = new ArrayList<>();
    
    protected final <T extends Closeable> T register(T resource) {
        resources.add(resource);
        return resource;
    }
    
    @Override
    public void close() throws IOException {
        // Close all registered resources
        for (Closeable r : resources) {
            try {
                r.close();
            } catch (IOException ex) {
                LOG.warn("Unable to close resource: " + ex.getLocalizedMessage());
            }
        }
    }
}
