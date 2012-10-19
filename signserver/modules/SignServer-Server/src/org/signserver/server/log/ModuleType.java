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
 * Different types of modules used by the SystemLogger.
 * @author Markus Kilås
 * @version $Id$
 */
public enum ModuleType {
    SERVICE,
    GLOBAL_CONFIG,
    WORKER_CONFIG,
    KEY_MANAGEMENT,   
    WORKER, 
    STATUS_REPOSITORY, 
}
