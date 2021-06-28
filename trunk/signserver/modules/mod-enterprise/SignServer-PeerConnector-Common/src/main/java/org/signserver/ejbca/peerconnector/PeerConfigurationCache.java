/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector;

import java.util.HashMap;
import java.util.Properties;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.configuration.ConfigurationCache;

/**
 * Class Holding cache variable for peer configuration.
 * 
 * Needed because EJB spec does not allow volatile, non-final fields in session beans.
 * 
 * @version $Id$
 */
public class PeerConfigurationCache implements ConfigurationCache {

    /**
     * Cache variable containing the peer configuration. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */
    private volatile ConfigurationBase cache = null;
    /** help variable used to control that updates are not performed to often. */
    private volatile long lastUpdateTime = -1;  

    @Override
    public boolean needsUpdate() {
        return cache==null || lastUpdateTime + CesecoreConfiguration.getCacheGlobalConfigurationTime() < System.currentTimeMillis();
    }

    @Override
    public void clearCache() {
        cache = null;
    }

    @Override
    public String getConfigId() {
        if (cache==null) {
            return getNewConfiguration().getConfigurationId();
        }
        return cache.getConfigurationId();
    }

    @Override
    public void saveData() {
       cache.saveData();
    }

    @Override
    public ConfigurationBase getConfiguration() {
        return cache;
    }
    
    @SuppressWarnings("rawtypes")
    @Override
    public ConfigurationBase getConfiguration(final HashMap data) {
        final ConfigurationBase returnval = getNewConfiguration();
        returnval.loadData(data);
        return returnval;
    }

    @Override
    public void updateConfiguration(final ConfigurationBase configuration) {
        cache = configuration;
        lastUpdateTime = System.currentTimeMillis();
    }
    
    @Override
    public ConfigurationBase getNewConfiguration() {
       return new PeerConfiguration();      
    }

    @Override
    public Properties getAllProperties() {
        return ((PeerConfiguration)cache).getAsProperties();
    }
}
