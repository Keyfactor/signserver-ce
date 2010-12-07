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
import java.util.Properties;
import javax.ejb.EJB;
import org.apache.log4j.Logger;
import org.signserver.common.ServiceLocator;
import org.signserver.ejb.interfaces.IStatusRepositorySession;

/**
 * ITimeSource taking the current time from the computer clock in case it has
 * not been manually disabled.
 *
 * It reads a status property INSYNC from the status repository.
 * It has no defined worker properties.
 *
 * $Id$
 */
public class StatusReadingLocalComputerTimeSource implements ITimeSource {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            StatusReadingLocalComputerTimeSource.class);

    /** Status property set to true if the time is in sync. */
    private static final String INSYNC = "INSYNC";

    /** Status repository session. */
    @EJB
    private transient IStatusRepositorySession.IRemote statusSession;


    /**
     * @param props Properties for this TimeSource (not used)
     * @see org.signserver.server.ITimeSource#init(java.util.Properties)
     */
    public void init(final Properties props) {
        try {
            statusSession = ServiceLocator.getInstance().lookupRemote(
                        IStatusRepositorySession.IRemote.class);
        } catch (Exception ex) {
            LOG.error("Looking up status repository session", ex);
        }
    }

    /**
     * Main method that should retrieve the current time from the device.
     * @return an accurate current time or null if it is not available.
     */
    public Date getGenTime() {
        Date date = null;
        if (Boolean.valueOf(statusSession.getProperty(INSYNC))) {
            date = new Date();
        }
        return date;
    }

}
