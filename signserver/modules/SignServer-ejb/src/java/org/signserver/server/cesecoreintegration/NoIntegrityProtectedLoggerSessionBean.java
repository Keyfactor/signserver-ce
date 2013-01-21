/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
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
 * An alternative implementation of the SecurityEventsLogger interface. It handles the
 * creation of a signed log for an event.
 * 
 * This was created to evaluate the performance of using database integrity protection
 * instead of custom code for log singing.
 * 
 * @version $Id: IntegrityProtectedLoggerSessionBean.java 907 2011-06-22 14:42:15Z johane $
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
