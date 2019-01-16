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
package org.signserver.peers.ejb;

import java.util.Properties;
import java.util.Set;
import javax.ejb.Stateless;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.configuration.GlobalConfigurationData;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.signserver.ejbca.peerconnector.PeerConfiguration;

/**
 * Our version of EJBCA's GlobalConfigurationSessionBean, only supporting peer configuration.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@Stateless
public class PeersGlobalConfigurationSessionBean implements GlobalConfigurationSessionLocal {
    
    // TODO: Hardcoded for now
    private static final PeerConfiguration CONFIG = new PeerConfiguration();
    static {
        CONFIG.setPeerConnectorIncomingEnabled(true);
        CONFIG.setPeerConnectorOutgoingEnabled(true);
    }
    
    @Override
    public GlobalConfigurationData findByConfigurationId(String configurationId) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Set<String> getIds() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public ConfigurationBase getCachedConfiguration(String configID) {
        
        if (!configID.equals(PeerConfiguration.CONFIGURATION_ID)) {
            throw new UnsupportedOperationException("Unsupported configuration");
        }
        return CONFIG;
    }

    @Override
    public void flushConfigurationCache(String configID) {
        if (!configID.equals(PeerConfiguration.CONFIGURATION_ID)) {
            throw new UnsupportedOperationException("Unsupported configuration");
        }
        // NOP
    }

    @Override
    public Properties getAllProperties(AuthenticationToken admin, String configID) throws AuthorizationDeniedException {
        if (!configID.equals(PeerConfiguration.CONFIGURATION_ID)) {
            throw new UnsupportedOperationException("Unsupported configuration");
        }
        return CONFIG.getAsProperties();
    }

    @Override
    public void saveConfiguration(AuthenticationToken admin, ConfigurationBase conf) throws AuthorizationDeniedException {
        if (!conf.equals(PeerConfiguration.CONFIGURATION_ID)) {
            throw new UnsupportedOperationException("Unsupported configuration: " + conf.getClass().getName());
        }
    }

    // Add business logic below. (Right-click in editor and choose
    // "Insert Code > Add Business Method")
}
