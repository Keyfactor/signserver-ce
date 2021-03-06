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

import org.signserver.common.WorkerConfig;

/**
 * Constants used when parsing/dumping global and worker properties.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface PropertiesConstants {
    
    String IMPLEMENTATION_CLASS = WorkerConfig.IMPLEMENTATION_CLASS;
    String CRYPTOTOKEN_IMPLEMENTATION_CLASS = WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS;
    
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
    String AUTHORIZED_CLIENTS_GEN2 = "AUTHORIZED_CLIENTS_GEN2";
    String AUTHORIZED_CLIENTS_DOT_SUBJECT_DOT_TYPE = ".SUBJECT.TYPE";
    String AUTHORIZED_CLIENTS_DOT_SUBJECT_DOT_VALUE = ".SUBJECT.VALUE";
    String AUTHORIZED_CLIENTS_DOT_ISSUER_DOT_TYPE = ".ISSUER.TYPE";
    String AUTHORIZED_CLIENTS_DOT_ISSUER_DOT_VALUE = ".ISSUER.VALUE";
    String AUTHORIZED_CLIENTS_DOT_DESCRIPTION = ".DESCRIPTION";
    String AUTHORIZED_CLIENTS_DOT_VALUE = ".VALUE";
    String AUTHORIZED_CLIENTS_DOT_TYPE = ".TYPE";
    String AUTHCLIENT = "AUTHCLIENT";
    String SIGNERCERT = "SIGNERCERT";
    String SIGNERCERTCHAIN = "SIGNERCERTCHAIN";
    String NAME = "NAME";
    String CLASSPATH = "CLASSPATH";
    String SIGNERTOKEN = "SIGNERTOKEN";
    
    String KEYSTORE_DATA = "KEYSTORE_DATA";
}
