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

import java.io.Serializable;
import java.util.Properties;

import org.cesecore.configuration.ConfigurationBase;

/**
 * Configuration for the peer connector module stored in the database.
 * 
 * @version $Id$
 */
public class PeerConfiguration extends ConfigurationBase implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final float LATEST_VERSION = 1f;
    //private static final Logger log = Logger.getLogger(PeerConfiguration.class);

    public static final String CONFIGURATION_ID = "PEER";

    private static final String KEY_PEERCONNECTORIN = "peer.in.enabled";
    private static final String KEY_PEERCONNECTOROUT = "peer.out.enabled";

    /** @return true if the instance allows incoming peer connections. */
    public boolean isPeerConnectorIncomingEnabled() { return getBoolean(KEY_PEERCONNECTORIN, false); }
    /** Set to true if the instance allows incoming peer connections. */
    public void setPeerConnectorIncomingEnabled(final boolean enabledIncoming) { putBoolean(KEY_PEERCONNECTORIN, enabledIncoming); }
    /** @return true if the instance allows outgoing peer connections. */
    public boolean isPeerConnectorOutgoingEnabled() { return getBoolean(KEY_PEERCONNECTOROUT, true); }
    /** Set to true if the instance allows outgoing peer connections. */
    public void setPeerConnectorOutgoingEnabled(boolean enabledOutgoing) { putBoolean(KEY_PEERCONNECTOROUT, enabledOutgoing); }

    //
    // ConfigurationBase methods
    //

    @Override
    public String getConfigurationId() {
        return CONFIGURATION_ID;
    }

    public Properties getAsProperties() {
        final Properties properties = new Properties();
        properties.put(KEY_PEERCONNECTORIN, isPeerConnectorIncomingEnabled());
        properties.put(KEY_PEERCONNECTOROUT, isPeerConnectorOutgoingEnabled());
        return properties;
    }

    //
    // UpgradeableDataHashMap methods
    //
    
    @Override
    public float getLatestVersion(){
        return LATEST_VERSION;
    }

    @Override
    public void upgrade() {
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            data.put(VERSION,  Float.valueOf(LATEST_VERSION));          
        }
    }
}
