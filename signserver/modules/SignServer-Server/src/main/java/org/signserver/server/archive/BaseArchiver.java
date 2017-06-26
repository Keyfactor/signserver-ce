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
package org.signserver.server.archive;


import java.util.List;
import org.signserver.server.BaseComponent;

/**
 * Abstract base implementation of an archiver.
 * Currently implements a base version of error reporting.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public abstract class BaseArchiver extends BaseComponent implements Archiver {
    
    @Override
    public List<String> getFatalErrors() {
        return getFatalErrors(null);
    }
}
