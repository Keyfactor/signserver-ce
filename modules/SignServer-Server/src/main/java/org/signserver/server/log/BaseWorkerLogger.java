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
package org.signserver.server.log;

import java.util.LinkedList;
import java.util.List;
import org.signserver.server.IServices;

/**
 * Abstract base implementation of the IWorkerLogger interface.
 * Contains a default implementation of the getFatalErrors mechanism.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public abstract class BaseWorkerLogger implements IWorkerLogger {
    private final List<String> fatalErrors = new LinkedList<>();
    private boolean hasSetError = false;
    
    @Override
    public List<String> getFatalErrors(IServices services) {
        return fatalErrors;
    }
    
    /**
     * Adds a fatal error to the list of errors held by the base implementation.
     *
     * @param error An error string to add
     */
    public void addFatalError(final String error) {
        fatalErrors.add(error);
        hasSetError = true;
    }
    
    /**
     * Checks if any fatal errors has been added.
     * The base implementation of this method only checks if any error has
     * been added to the base implementation using <code>addFatalError()</code>.
     * Implementations overriding <code>getFatalErrors()</code> should override
     * this method or keep track of added errors if it needs to take this into
     * account i.e. as a runtime check.
     * 
     * @return True if any error has been added
     */
    public boolean hasErrors() {
        return hasSetError;
    }
}
