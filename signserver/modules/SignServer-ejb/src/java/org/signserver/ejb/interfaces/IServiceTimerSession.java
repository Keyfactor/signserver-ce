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
package org.signserver.ejb.interfaces;

import javax.ejb.Local;
import javax.ejb.Remote;

/**
 * Interface for ServiceTimerSession.
 *
 * @version $Id$
 */
public interface IServiceTimerSession {

    /**
     * Loads and activates one or all the services from database that are
     * active.
     * @param serviceId 0 indicates all services othervise is just the
     * specified service loaded.
     * @throws EJBException if a communication or other error occurs.
     */
    void load(int serviceId);

    /**
     * Cancels one or all existing timers.
     * @param serviceId indicates all services othervise is just the specified
     * service unloaded.
     * @throws EJBException if a communication or other error occurs.
     */
    void unload(int serviceId);

    /**
     * Adds a timer to the bean.
     * @throws EJBException if a communication or other error occurs.
     */
    void addTimer(long interval, Integer id);

    /**
     * Cancels a timer with the given Id.
     * @throws EJBException if a communication or other error occurs.
     */
    void cancelTimer(Integer id);

    @Remote
    interface IRemote extends IServiceTimerSession {

        String JNDI_NAME = "signserver/ServiceTimerSessionBean/remote";
    }

    @Local
    interface ILocal extends IServiceTimerSession {

        String JNDI_NAME = "signserver/ServiceTimerSessionBean/local";
    }
}
