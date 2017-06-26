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

import org.signserver.common.ResyncException;
import org.signserver.server.log.AdminInfo;

/**
 * Local EJB interface.
 * Mirrors methods which are audit-logged, taking an extra AdminInfo instance.
 *
 * @version $Id$
 */
@Local
public interface GlobalConfigurationSessionLocal extends GlobalConfigurationSession {
    
    /**
     * Method setting a global configuration property. For node. prefix will the
     * node id be appended.
     * @param adminInfo Administrator information
     * @param scope one of the GlobalConfiguration.SCOPE_ constants
     * @param key of the property should not have any scope prefix, never null
     * @param value the value, never null.
     */
    void setProperty(final AdminInfo adminInfo, String scope, String key, String value);

    /**
     * Method used to remove a property from the global configuration.
     * @param adminInfo Administrator information
     * @param scope one of the GlobalConfiguration.SCOPE_ constants
     * @param key of the property should start with either glob. or node.,
     * never null
     * @return true if removal was successful, othervise false.
     */
    boolean removeProperty(final AdminInfo adminInfo, String scope, String key);

    /**
     * Method that is used after a database crash to restore all cached data to
     * database.
     * @param adminInfo Administrator information
     * @throws ResyncException if resync was unsuccessfull
     */
    void resync(final AdminInfo adminInfo) throws ResyncException;

    /**
     * Method that is used after a database crash to restore all cached data to
     * database.
     * @param adminInfo Administrator information
     * @throws ResyncException if resync was unsuccessfull
     */
    void reload(final AdminInfo adminInfo);
}

