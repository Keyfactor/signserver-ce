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
package org.signserver.test.mock;

import java.util.List;
import java.util.Properties;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ResyncException;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;

/**
 * Mockup version of the GlobalConfigurationSessionBean.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class GlobalConfigurationSessionMock implements
        IGlobalConfigurationSession.IRemote,
        IGlobalConfigurationSession.ILocal {

    private GlobalConfiguration globalConfiguration;
    private Properties config = new Properties();

    public GlobalConfigurationSessionMock() {
         globalConfiguration = new GlobalConfiguration(config,
                 GlobalConfiguration.STATE_INSYNC);
    }

    public void setProperty(String scope, String key, String value) {
        config.setProperty(scope + key, value);
    }

    public boolean removeProperty(String scope, String key) {
        return config.remove(scope + key) != null;
    }

    public GlobalConfiguration getGlobalConfiguration() {
        return globalConfiguration;
    }

    public List<Integer> getWorkers(int workerType) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void resync() throws ResyncException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void reload() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
