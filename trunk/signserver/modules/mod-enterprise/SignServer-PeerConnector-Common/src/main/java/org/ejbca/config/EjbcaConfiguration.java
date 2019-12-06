/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.config;

import org.signserver.common.CompileTimeSettings;

/**
 * Configuration needed by the peers implementation.
 *
 * The SignServer version of the class with the same name from EJBCA.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class EjbcaConfiguration {

    public static boolean isPeerSoKeepAlive() {
        return Boolean.parseBoolean(CompileTimeSettings.getInstance().getProperty("peerconnector.connection.sokeepalive"));
    }

    public static boolean isPeerTcpNoDelay() {
        return Boolean.parseBoolean(CompileTimeSettings.getInstance().getProperty("peerconnector.connection.tcpnodelay"));
    }

    public static int getPeerSoTimeoutMillis() {
        return Integer.parseInt(CompileTimeSettings.getInstance().getProperty("peerconnector.connection.sotimeout"));
    }

    public static int getPeerMaxPoolSize() {
        return Integer.parseInt(CompileTimeSettings.getInstance().getProperty("peerconnector.connection.maxpoolsize"));
    }

    public static long getPeerIncomingAuthCacheTimeMillis() {
        return Long.parseLong(CompileTimeSettings.getInstance().getProperty("peerconnector.incoming.authcachetime"));
    }

    public static int getPeerIncomingMaxMessageSize() {
        return Integer.parseInt(CompileTimeSettings.getInstance().getProperty("peerconnector.incoming.maxmessagesize"));
    }
    
}
