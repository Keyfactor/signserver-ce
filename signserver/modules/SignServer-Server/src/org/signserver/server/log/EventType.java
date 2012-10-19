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
package org.signserver.server.log;

/**
 * Different types of log events used by the SystemLogger.
 * @author Markus Kilås
 * @version $Id$
 */
public enum EventType {
    SIGNSERVER_STARTUP,
    SIGNSERVER_SHUTDOWN,
    
    GLOBAL_CONFIG_RELOAD,
    GLOBAL_CONFIG_RESYNC,
    REMOVE_GLOBAL_PROPERTY, 
    SET_GLOBAL_PROPERTY,
    
    SET_WORKER_CONFIG,
    REMOVE_WORKER_PROPERTY,
    CERTINSTALLED,
    CERTCHAININSTALLED,
    KEYSELECTED,
    
    SET_STATUS_PROPERTY,
    
    KEYGEN,
    KEYTEST,
    GENCSR,
    
    PROCESS,
}
