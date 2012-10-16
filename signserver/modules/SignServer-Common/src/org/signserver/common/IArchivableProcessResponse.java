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
package org.signserver.common;

import java.util.Collection;
import org.signserver.server.archive.Archivable;

/**
 * Interface that should be implemented by all process responses that could be archived.
 * 
 * @author phive
 * @version $Id$
 */
public interface IArchivableProcessResponse {

    /**
     * Method that should return an Id of the archived data could be
     * the response serialnumber.
     * 
     * return null of not implemented.
     */
    String getArchiveId();
    
    /**
     * @return A collection of all Archivables in the response.
     */
    Collection<? extends Archivable> getArchivables();
}
