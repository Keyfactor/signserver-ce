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
package org.signserver.server.integrityprotected;

import java.util.Map;
import java.util.Properties;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.impl.integrityprotected.IntegrityProtectedLoggerSessionLocal;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.time.TrustedTime;

/**
 * Customized version of IntegrityProtectedLoggerSessionLocal that adds an method for storing a log row with a specified sequence number.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface SequencialIntegrityProtectedLoggerSessionLocal extends IntegrityProtectedLoggerSessionLocal {

    /**
     * Creates a signed log and stores in database with the provided sequence number.
     *
     * @param trustedTime TrustedTime instance will be used to get a trusted timestamp.
     * @param eventType The event log type.
     * @param eventStatus The status of the operation to log.
     * @param module The module where the operation took place.
     * @param service The service(application) that performed the operation.
     * @param authToken The authentication token that invoked the operation.
     * @param customId
     * @param additionalDetails Additional details to be logged.
     * @param searchDetail2
     * @param searchDetail1
     * @param properties properties to be passed on the device
     * @param sequenceNumber to use for this row
     *
     * @throws AuditRecordStorageException if unable to store the log record
     */
    void logWithSequenceNumber(TrustedTime trustedTime, EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service, String authToken,
            String customId, String searchDetail1, String searchDetail2, Map<String, Object> additionalDetails, Properties properties, Long sequenceNumber) throws AuditRecordStorageException;
}
