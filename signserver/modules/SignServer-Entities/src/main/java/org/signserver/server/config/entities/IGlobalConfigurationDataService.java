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
package org.signserver.server.config.entities;

import java.util.List;

/**
 * DataService managing the persistence of the global configuration data.
 *
 * @version $Id$
 */
public interface IGlobalConfigurationDataService {

    /**
     * @return All global configuration beans
     */
    List<GlobalConfigurationDataBean> findAll();

    /**
     * Tries to remove the given global configuration property.
     * @param completekey property to remove
     * @return True if the property existed and was removed
     */
    boolean removeGlobalProperty(String completekey);

    /**
     * Sets the given global configuration property.
     * @param completekey property to set
     * @param value the value to set
     */
    void setGlobalProperty(String completekey, String value);
    
}
