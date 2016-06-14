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

import java.util.LinkedList;
import java.util.List;

/**
 * Base implementation of the component interface.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public abstract class BaseComponent implements IComponent {

    private final List<String> fatalErrors = new LinkedList<>();

    /**
     * Register a fatal error for the archiver instance.
     * 
     * @param error 
     */
    protected void addFatalError(final String error) {
        fatalErrors.add(error);
    }
    
    @Override
    public List<String> getFatalErrors(IServices services) {
        return fatalErrors;
    }
}
