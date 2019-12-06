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
package org.signserver.client.cli.defaultimpl;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import org.apache.log4j.Logger;
import org.signserver.common.IllegalRequestException;

/**
 * Handles a bit of plumbing for the file specific handlers.
 *
 * The input and output files are provided.
 * Resources can be registered with <i>closeLater()</i> to be closed when
 * the instance is being closed.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class AbstractFileSpecificHandler implements FileSpecificHandler {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AbstractFileSpecificHandler.class);

    private final File inFile;
    private final File outFile;
    private final ArrayList<Closeable> resources = new ArrayList<>(2);

    public AbstractFileSpecificHandler(File inFile, File outFile) {
        this.inFile = inFile;
        this.outFile = outFile;
    }

    /**
     * @return The input file to read from
     */
    protected final File getInFile() {
        return inFile;
    }

    /**
     * @return The output file to write to
     */
    protected final File getOutFile() {
        return outFile;
    }

    /**
     * Add the resource to be closed when close is called on the handler.
     *
     * @param <T> The provided resource (for convenience).
     * @param resource The resource to be closed later.
     * @return 
     */
    protected final <T extends Closeable> T closeLater(T resource) {
        resources.add(resource);
        return resource;
    }
    
    @Override
    public void close() {
        // Close all registered resources
        for (Closeable r : resources) {
            try {
                r.close();
            } catch (IOException ex) {
                LOG.warn("Unable to close resource: " + ex.getLocalizedMessage());
            }
        }
    }

    @Override
    public InputSource producePreRequestInput() throws IOException, IllegalRequestException {
        // return null for default implementation
        return null;
    }

    @Override
    public void assemblePreResponse(OutputCollector oc) throws IOException, IllegalArgumentException {
        // Do nothing in default implementation
    }
    
}
