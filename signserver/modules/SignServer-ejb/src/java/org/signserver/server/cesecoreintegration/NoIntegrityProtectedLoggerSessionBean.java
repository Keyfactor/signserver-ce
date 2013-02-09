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
package org.signserver.server.cesecoreintegration;

import java.util.Map;
import java.util.Properties;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.impl.integrityprotected.IntegrityProtectedLoggerSessionLocal;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.time.TrustedTime;

/**
 * An IntegrityProtectedLoggerSession not doing any actual secure logging.
 *
 * This implementation is only included so that we can deploy SignServer without
 * database in the NODB mode.
 *
 * Based on IntegrityProtectedLoggerSessionBean.java from CESeCore.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class NoIntegrityProtectedLoggerSessionBean implements IntegrityProtectedLoggerSessionLocal {

    private static final Logger log = Logger.getLogger(NoIntegrityProtectedLoggerSessionBean.class);

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)	// Always persist audit log
    public void log(final TrustedTime trustedTime, final EventType eventType, final EventStatus eventStatus, final ModuleType module, final ServiceType service,
            final String authToken, final String customId, final String searchDetail1, final String searchDetail2, final Map<String, Object> additionalDetails,
            final Properties properties) throws AuditRecordStorageException {
        if (log.isTraceEnabled()) {
            log.trace(String.format(">log:%s:%s:%s:%s:%s:%s", eventType, eventStatus, module, service, authToken, additionalDetails));
        }

        if (log.isDebugEnabled()) {
            log.debug("Not logging to database");
        }

        if (log.isTraceEnabled()) {
            log.trace("<log");
        }
    }
}
