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

import org.cesecore.audit.enums.EventType;

/**
 * Different types of log events used by the SystemLogger.
 * @author Markus Kilås
 * @version $Id$
 */
public enum SignServerEventTypes implements EventType {
    
    /** Logged at startup of the SignServer application. */
    SIGNSERVER_STARTUP,
    /** Logged at shutdown of the SignServer application. */
    SIGNSERVER_SHUTDOWN,
    
    /** Logged when a global configuration property was updated. */
    SET_GLOBAL_PROPERTY,
    /** Logged when a global configuration property was removed. */
    REMOVE_GLOBAL_PROPERTY, 
    /** Logged when the global configuration was reloaded from the database. */
    GLOBAL_CONFIG_RELOAD,
    /** Logged when the resync command was executed. */
    GLOBAL_CONFIG_RESYNC,
    
    /** Logged when a worker's configuration was updated by adding and/or removing and/or changing any values. */
    SET_WORKER_CONFIG,
    /** Logged when a certificate was uploaded to the worker configuration. */
    CERTINSTALLED,
    /** Logged when a certificate chain was uploaded to the worker configuration. */
    CERTCHAININSTALLED,
    /** Logged when the key-pair to use was selected by changing the value of the DEFAULTKEY worker property. */
    KEYSELECTED,
    
    /** Logged when a new key-pair was generated using the built-in key generation command. */
    KEYGEN,
    /** Logged when the key test command was executed and a test signing with either the specified key or all keys in the slot if that was specified. */
    KEYTEST,
    /** Logged when a certificate signing request (CSR) was generated. */
    GENCSR,
    
    /** Logged when a status property was updated. */
    SET_STATUS_PROPERTY,
    
    /** Logged for events regarding worker processing but when a worker logger can not be used because the requested worker does not exist etc. */
    PROCESS;
    
   @Override
   public boolean equals(EventType value) {
       if (value == null) {
           return false;
       }
       return this.toString().equals(value.toString());
    }

}
