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

import java.util.Date;
import java.util.List;
import java.util.Properties;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerStatusInfo;

/**
 * Interface defining an accurate time source, could be the local computer
 * clock or a connection to a time device.
 *
 * Its main function is getGenTime returning a java.util.Date
 *
 * @author philip
 * @version $Id$
 */
public interface ITimeSource {

    /**
     * Method called after creation of instance.
     * @param props the signers properties
     */
    void init(Properties props);

    /**
     * Main method that should retrieve the current time from the device.
     * @param context of the request
     * @return an accurate current time or null if it is not available.
     * @throws SignServerException if the timesource was misconfigured
     */
    Date getGenTime(RequestContext context) throws SignServerException;
    
    /**
     * Get brief status entries to be presented in worker statuses.
     *
     * @return List of status entries
     */
    List<WorkerStatusInfo.Entry> getStatusBriefEntries();
    
    /**
     * Get complete status entries to be presented in worker statuses.
     * 
     * @return List of complete status entries 
     */
    List<WorkerStatusInfo.Entry> getStatusCompleteEntries();
}
