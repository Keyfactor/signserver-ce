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
    String SIGNERCERTIFICATE = ".SIGNERCERTIFICATE";
    String SIGNERCERTCHAIN = ".SIGNERCERTCHAIN";
    String AUTHCLIENT = ".AUTHCLIENT";
    String GLOBAL_PREFIX = "GLOB.";
    String NODE_PREFIX = "NODE.";
    String WORKER_PREFIX = "WORKER";
    String OLDWORKER_PREFIX = "SIGNER";
    String REMOVE_PREFIX = "-";
    String GENID = "GENID";
}
