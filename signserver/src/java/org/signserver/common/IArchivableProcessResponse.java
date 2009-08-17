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

/**
 * Interface that should be implemented by all process responses that could be archived.
 * 
 * @author phive
 *
 */
public interface IArchivableProcessResponse {

	
    /**
     * Method that should return an Id of the archived data could be
     * the response serialnumber.
     * 
     * return null of not implemented.
     */
    public String getArchiveId();
    
    /**
     * Method that should return a archive data object used for achiving.
     * return null if not implemented.
     */
    public ArchiveData getArchiveData();
}
