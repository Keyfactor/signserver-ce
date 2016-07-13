/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.data.impl;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import org.apache.log4j.Logger;

/**
 *
 * @author user
 */
public class ResourcesAutoCloseable implements AutoCloseable {

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
