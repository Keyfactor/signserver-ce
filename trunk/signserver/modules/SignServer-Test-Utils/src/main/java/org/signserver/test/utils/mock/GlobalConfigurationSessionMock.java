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
package org.signserver.test.utils.mock;

import java.util.Properties;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ResyncException;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionRemote;
import org.signserver.server.log.AdminInfo;

/**
 * Mockup version of the GlobalConfigurationSessionBean.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class GlobalConfigurationSessionMock implements
        GlobalConfigurationSessionRemote,
        GlobalConfigurationSessionLocal {

    private GlobalConfiguration globalConfiguration;
    private final Properties config;

    public GlobalConfigurationSessionMock() {
         this(new Properties());
    }
    
    public GlobalConfigurationSessionMock(Properties config) {
        this.config = config;
         globalConfiguration = new GlobalConfiguration(config,
                 GlobalConfiguration.STATE_INSYNC, "SignServer 4.7.11alpha0");
    }

    @Override
    public void setProperty(String scope, String key, String value) {
        config.setProperty(scope + key, value);
    }
    
    @Override
    public void setProperty(AdminInfo adminInfo, String scope, String key, String value) {
        config.setProperty(scope + key, value);
    }


    @Override
    public boolean removeProperty(String scope, String key) {
        return config.remove(scope + key) != null;
    }

    @Override
    public boolean removeProperty(AdminInfo adminInfo, String scope, String key) {
        return config.remove(scope + key) != null;
    }

    @Override
    public GlobalConfiguration getGlobalConfiguration() {
        return globalConfiguration;
    }

    @Override
    public void resync() throws ResyncException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void resync(AdminInfo adminInfo) throws ResyncException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    @Override
    public void reload() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void reload(AdminInfo adminInfo) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    
}
