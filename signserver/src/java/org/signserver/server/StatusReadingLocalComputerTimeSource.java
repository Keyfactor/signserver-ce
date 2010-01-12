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
import java.util.Hashtable;
import java.util.Properties;
import javax.naming.Context;
import javax.naming.InitialContext;
import org.apache.log4j.Logger;
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
    private transient IStatusRepositorySession.ILocal statusSession;


    /**
     * @param props Properties for this TimeSource (not used)
     * @see org.signserver.server.ITimeSource#init(java.util.Properties)
     */
    public void init(final Properties props) {
        try {
            statusSession = (IStatusRepositorySession.ILocal)
                getInitialContext().lookup(
                    IStatusRepositorySession.ILocal.JNDI_NAME);
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

    /**
     * Get the initial naming context
     */
    protected Context getInitialContext() throws Exception {
        final Hashtable<String, String> props = new Hashtable<String, String>();
        props.put(
                Context.INITIAL_CONTEXT_FACTORY,
                "org.jnp.interfaces.NamingContextFactory");
        props.put(
                Context.URL_PKG_PREFIXES,
                "org.jboss.naming:org.jnp.interfaces");
        props.put(Context.PROVIDER_URL, "jnp://localhost:1099");
        return new InitialContext(props);
    }
}
