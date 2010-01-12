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

import java.util.Map;
import javax.ejb.Local;
import javax.ejb.Remote;
import org.signserver.common.StatusRepositoryData;

/**
 * Interface towards the status repository session bean.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public interface IStatusRepositorySession {

    /**
     * Get a property.
     *
     * @param key Key to get the value for
     * @return The value if existing and not expired, otherwise null
     */
    String getProperty(String key);

    /**
     * Set a property without expiration, the value will live until the
     * application is restarted.
     *
     * @param key The key to set the value for
     * @param value The value to set
     */
    void setProperty(String key, String value);

     /**
     * Set a property with a given expiration timestamp.
     *
     * After the expiration the get method will return null.
     *
     * @param key The key to set the value for
     * @param value The value to set
     */
    void setProperty(String key, String value, long expiration);

    /**
     * Removes a property.
     *
     * @param key The property to remove.
     */
    void removeProperty(String key);

    /**
     * @return An unmodifiable map of all properties
     */
    Map<String,StatusRepositoryData> getProperties();

    /**
     * Remote interface.
     */
    @Remote
    interface IRemote extends IStatusRepositorySession {

        String JNDI_NAME = "signserver/StatusRepositorySessionBean/remote";
    }

    /**
     * Local interface.
     */
    @Local
    interface ILocal extends IStatusRepositorySession {

        String JNDI_NAME = "signserver/StatusRepositorySessionBean/local";
    }
}
