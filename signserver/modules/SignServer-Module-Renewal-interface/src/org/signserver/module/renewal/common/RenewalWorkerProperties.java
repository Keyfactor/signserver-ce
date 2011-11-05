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
package org.signserver.module.renewal.common;

/**
 * Properties used by the RenewalWorker.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface RenewalWorkerProperties {


    /** The worker to renew. **/
    String REQUEST_WORKER = "WORKER";

    /** True if the key should be renewed. **/
    String REQUEST_FORDEFAULTKEY = "FORDEFAULTKEY";
    String REQUEST_FORDEFAULTKEY_TRUE = Boolean.TRUE.toString();
    String REQUEST_FORDEFAULTKEY_FALSE = Boolean.FALSE.toString();
    String REQUEST_AUTHCODE = "AUTHCODE";

    String RESPONSE_RESULT = "RESULT";

    String RESPONSE_RESULT_OK = "OK";
    String RESPONSE_RESULT_FAILURE = "FAILURE";
    String RESPONSE_MESSAGE = "MESSAGE";

    String WORKERPROPERTY_RENEWWORKER = "RENEWWORKER";

    String LOG_RENEWEE = "RENEWEE";

    String LOG_GENERATEDKEYALIAS = "GENERATEDKEYALIAS";
    String LOG_GENERATEDKEYHASH = "GENERATEDKEYHASH";

    String LOG_NEWCERTSERIALNO = "NEWCERTSERIALNO";
    String LOG_NEWCERTSUBJECTDN = "NEWCERTSUBJECTDN";
    String LOG_NEWCERTISSUERDN = "NEWCERTISSUERDN";

    String LOG_RESPONSE_RESULT = "RESPONSE_RESULT";
    String LOG_RESPONSE_MESSAGE = "RESPONSE_MESSAGE";
}
