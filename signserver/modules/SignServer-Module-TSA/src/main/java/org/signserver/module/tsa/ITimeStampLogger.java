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
package org.signserver.module.tsa;

import org.signserver.server.log.IWorkerLogger;

/**
 * WorkerLogger for TimeStampSigner.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface ITimeStampLogger extends IWorkerLogger {

    String LOG_TSA_TIME = "TSA_TIME";
    String LOG_TSA_SERIALNUMBER = "TSA_SERIALNUMBER";
    String LOG_TSA_EXCEPTION = "TSA_EXCEPTION";

    String LOG_TSA_PKISTATUS = "TSA_PKISTATUS";

    String LOG_TSA_PKISTATUS_STRING = "TSA_PKISTATUS_STRING";

    String LOG_TSA_PKIFAILUREINFO = "TSA_PKIFAILUREINFO";

    String LOG_TSA_POLICYID = "TSA_POLICYID";

    String LOG_TSA_TIMESTAMPREQUEST_CERTREQ = "TSA_TIMESTAMPREQUEST_CERTREQ";

    String LOG_TSA_TIMESTAMPREQUEST_CRITEXTOIDS = "TSA_TIMESTAMPREQUEST_CRITEXTOIDS";

    String LOG_TSA_TIMESTAMPREQUEST_ENCODED = "TSA_TIMESTAMPREQUEST_ENCODED";

    String LOG_TSA_TIMESTAMPREQUEST_NONCRITEXTOIDS = "TSA_TIMESTAMPREQUEST_NONCRITEXTOIDS";

    String LOG_TSA_TIMESTAMPREQUEST_NOUNCE = "TSA_TIMESTAMPREQUEST_NOUNCE";

    String LOG_TSA_TIMESTAMPREQUEST_VERSION = "TSA_TIMESTAMPREQUEST_VERSION";

    String LOG_TSA_TIMESTAMPREQUEST_MESSAGEIMPRINTALGOID =
            "TSA_TIMESTAMPREQUEST_MESSAGEIMPRINTALGOID";

    String LOG_TSA_TIMESTAMPREQUEST_MESSAGEIMPRINTDIGEST =
            "TSA_TIMESTAMPREQUEST_MESSAGEIMPRINTDIGEST";

    String LOG_TSA_TIMESTAMPRESPONSE_ENCODED = "TSA_TIMESTAMPRESPONSE_ENCODED";
}
