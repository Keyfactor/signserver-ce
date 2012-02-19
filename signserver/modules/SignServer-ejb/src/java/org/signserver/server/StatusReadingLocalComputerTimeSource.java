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
import org.signserver.statusrepo.common.StatusEntry;
import org.signserver.statusrepo.common.NoSuchPropertyException;
import org.signserver.statusrepo.IStatusRepositorySession;
import org.signserver.statusrepo.common.StatusName;

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

    /** Status repository session. */
    @EJB
    private IStatusRepositorySession.IRemote statusSession;

    private StatusName insyncPropertyName = StatusName.INSYNC;

    /**
     * @param props Properties for this TimeSource (not used)
     * @see org.signserver.server.ITimeSource#init(java.util.Properties)
     */
    @Override
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
    @Override
    public Date getGenTime() {
        try {
            Date date = null;
            StatusEntry entry = statusSession.getValidEntry(insyncPropertyName.name());
            if (entry != null && Boolean.valueOf(entry.getValue())) {
                date = new Date();
            }
            return date;
        } catch (NoSuchPropertyException ex) {
            throw new RuntimeException(ex);
        }
    }

}
