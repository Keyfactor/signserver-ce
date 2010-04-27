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
package org.signserver.server;

import java.util.Map;
import java.util.Properties;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface IWorkerLogger {

    // Log constants
    String LOG_ID = "LOG_ID";
    String LOG_TIME = "LOG_TIME";
    String LOG_REPLY_TIME = "REPLY_TIME";
    String LOG_CLIENT_AUTHORIZED = "CLIENT_AUTHORIZED";
    String LOG_CLIENT_IP = "CLIENT_IP";
    String LOG_EXCEPTION = "EXCEPTION";
    String LOG_PROCESS_SUCCESS = "PROCESS_SUCCESS";
    String LOG_WORKER_AUTHTYPE = "WORKER_AUTHTYPE";
    String LOG_WORKER_ID = "WORKER_ID";
    String LOG_CLIENT_CERT_SUBJECTDN = "CLIENT_CERT_SUBJECTDN";
    String LOG_CLIENT_CERT_ISSUERDN = "CLIENT_CERT_ISSUERDN";
    String LOG_CLIENT_CERT_SERIALNUMBER = "CLIENT_CERT_SERIALNUMBER";
    String LOG_SIGNER_CERT_SUBJECTDN = "SIGNER_CERT_SUBJECTDN";
    String LOG_SIGNER_CERT_ISSUERDN = "SIGNER_CERT_ISSUERDN";
    String LOG_SIGNER_CERT_SERIALNUMBER = "SIGNER_CERT_SERIALNUMBER";

    String LOG_REQUEST_FULLURL = "REQUEST_FULLURL";
    String LOG_REQUEST_LENGTH = "REQUEST_LENGTH";
    String LOG_FILENAME = "FILENAME";
    String LOG_XFORWARDEDFOR = "XFORWARDEDFOR";

    String LOG_PURCHASED = "PURCHASED";


    /**
     * Method called after creation of instance.
     * @param props the signers properties
     */
    void init(Properties props);

    void log(Map<String,String> entries) throws WorkerLoggerException;

}
