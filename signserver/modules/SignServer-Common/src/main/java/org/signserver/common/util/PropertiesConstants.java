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
package org.signserver.common.util;

/**
 * Constants used when parsing/dumping global and worker properties.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface PropertiesConstants {
    String DOT_SIGNERCERTIFICATE = ".SIGNERCERTIFICATE";
    
    String DOT_SIGNERCERTCHAIN = ".SIGNERCERTCHAIN";
    String DOT_AUTHCLIENT = ".AUTHCLIENT";
    String GLOBAL_PREFIX_DOT = "GLOB.";
    String NODE_PREFIX_DOT = "NODE.";
    String WORKER_PREFIX = "WORKER";
    String OLDWORKER_PREFIX = "SIGNER";
    String REMOVE_PREFIX = "-";
    String GENID = "GENID";
    
    String AUTHORIZED_CLIENTS = "AUTHORIZED_CLIENTS";
    String SIGNERCERT = "SIGNERCERT";
    String SIGNERCERTCHAIN = "SIGNERCERTCHAIN";
    String NAME = "NAME";
}
