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

import java.util.List;
import java.util.Map;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.IServices;
import org.signserver.server.SignServerContext;

/**
 * Logger for events (transactions) performed by a worker processing a request.
 * Audit events not associated with a worker transaction should be logged by a
 * system logger instead.
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
    String LOG_WORKER_NAME = "WORKER_NAME";
    String LOG_CLIENT_CERT_SUBJECTDN = "CLIENT_CERT_SUBJECTDN";
    String LOG_CLIENT_CERT_ISSUERDN = "CLIENT_CERT_ISSUERDN";
    String LOG_CLIENT_CERT_SERIALNUMBER = "CLIENT_CERT_SERIALNUMBER";
    String LOG_SIGNER_CERT_SUBJECTDN = "SIGNER_CERT_SUBJECTDN";
    String LOG_SIGNER_CERT_ISSUERDN = "SIGNER_CERT_ISSUERDN";
    String LOG_SIGNER_CERT_SERIALNUMBER = "SIGNER_CERT_SERIALNUMBER";
    
    /** The key alias used. */
    String LOG_KEYALIAS = "KEYALIAS";
    /** The key algorithm used. */
    String LOG_KEY_ALGORITHM = "KEY_ALGORITHM";
    /** The key specification used. */
    String LOG_KEY_SPECIFICATION = "KEY_SPECIFICATION";

    /**
     * The configured crypto token, or if none configured the name of the worker
     * involved or its worker ID.
     */
    String LOG_CRYPTOTOKEN = "CRYPTOTOKEN";

    String LOG_REQUEST_FULLURL = "REQUEST_FULLURL";
    String LOG_REQUEST_LENGTH = "REQUEST_LENGTH";
    String LOG_FILENAME = "FILENAME";
    String LOG_XFORWARDEDFOR = "XFORWARDEDFOR";
    
    /** Custom value fed from an HTTP header. */
    String LOG_XCUSTOM1 = "XCUSTOM1";

    /** Indicating if the purchase was granted by any configured Accounter implementations. */
    String LOG_PURCHASED = "PURCHASED";

    String LOG_PDF_PASSWORD_SUPPLIED = "PDF_PASSWORD_SUPPLIED";
    
    String LOG_ARCHIVE_IDS = "ARCHIVE_IDS";

    String LOG_RESPONSE_ENCODED = "RESPONSE_ENCODED";
    String LOG_REQUEST_DIGEST = "REQUEST_DIGEST";
    String LOG_REQUEST_DIGEST_ALGORITHM = "REQUEST_DIGEST_ALGORITHM";
    String LOG_RESPONSE_DIGEST = "RESPONSE_DIGEST";
    String LOG_RESPONSE_DIGEST_ALGORITHM = "RESPONSE_DIGEST_ALGORITHM";

    /**
     * Method called after creation of instance.
     * @param workerId for this worker
     * @param config for this worker
     * @param context can contain dependencies such as an EntityManager (to only use during initialization).
     */
    void init(int workerId, WorkerConfig config, SignServerContext context);

    /**
     * Write out the log line. What fields that are placed in the actual log
     * and in which order etc is up to the implementing IWorkerLogger.
     *
     * @param adminInfo
     * @param fields Fields that potentially could be placed in the log entry.
     * @param requestContext the request context
     * @throws WorkerLoggerException In case there is a problem writing the log.
     */
    void log(final AdminInfo adminInfo, Map<String, Object> fields, RequestContext requestContext) throws WorkerLoggerException;

    /**
     * Return a list of fatal errors for the logger implementation.
     * 
     * @param services Services instance, can be used by implementations
     *                 when gathering errors
     * @return A list of errors, or empty if there's no fatal errors
     */
    List<String> getFatalErrors(IServices services);
}
