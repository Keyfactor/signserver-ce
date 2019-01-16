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
