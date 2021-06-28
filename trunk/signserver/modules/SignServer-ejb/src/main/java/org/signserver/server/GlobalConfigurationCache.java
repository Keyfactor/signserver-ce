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

import java.util.Properties;
import org.signserver.common.GlobalConfiguration;

/**
 * Cache used to store temporary data during a database failure
 * Should only be used from the GlobalConfigurationSessionBean!
 * 
 * FIXME: Move closer to GlobalConfigurationSessionBean and maybe shouldn't be public.
 * 
 * @author Philip Vendil 2007 jan 22
 *
 * @version $Id$
 */
public class GlobalConfigurationCache {

    private static final GlobalConfigurationCache INSTANCE = new GlobalConfigurationCache();
    
    /**
     * Cached configuration used for non-synced state.
     */
    private Properties cachedGlobalConfig;
    private String currentState = GlobalConfiguration.STATE_INSYNC;

    private GlobalConfigurationCache() {}
    
    public static GlobalConfigurationCache getInstance() {
        return INSTANCE;
    }

    public synchronized Properties getCachedGlobalConfig() {
        return cachedGlobalConfig;
    }

    public synchronized void setCachedGlobalConfig(final Properties cachedGlobalConfig) {
        this.cachedGlobalConfig = cachedGlobalConfig;
    }

    public synchronized String getCurrentState() {
        return currentState;
    }

    public synchronized void setCurrentState(final String currentState) {
        this.currentState = currentState;
    }
}
