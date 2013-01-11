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

import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Appender;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.ErrorHandler;
import org.cesecore.audit.AuditLogDevice;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.AuditExporter;
import org.cesecore.audit.audit.AuditLogExportReport;
import org.cesecore.audit.audit.AuditLogExporterException;
import org.cesecore.audit.audit.AuditLogValidationReport;
import org.cesecore.audit.audit.AuditLogValidatorException;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.impl.log4j.Log4jDeviceErrorHandler;
import org.cesecore.audit.log.AuditLogResetException;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.time.TrustedTime;
import org.cesecore.util.query.QueryCriteria;

/**
 * Audit log device implementing Log4J logging using
 * the log format used by the old SignServer SystemLogger
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */

public class SignServerLog4jDevice implements AuditLogDevice {
	private static final Logger LOG = Logger.getLogger(SignServerLog4jDevice.class);
	private static final String UNSUPPORTED = SignServerLog4jDevice.class.getSimpleName() + " does not support query, verification or export operations.";
	private final List<Log4jDeviceErrorHandler> errorHandlers = new ArrayList<Log4jDeviceErrorHandler>();
	
	public SignServerLog4jDevice() {
		final Enumeration<Appender> enumeration = LOG.getAllAppenders();
		while (enumeration.hasMoreElements()) {
			final Appender appender = enumeration.nextElement();
			final ErrorHandler errorHandler = appender.getErrorHandler();
			if (errorHandler != null) {
				final Log4jDeviceErrorHandler wrappedErrorHandler = new Log4jDeviceErrorHandler(errorHandler);
				errorHandlers.add(wrappedErrorHandler);
				appender.setErrorHandler(wrappedErrorHandler);
			}
		}
	}
	
	private void assertNoErrors() throws AuditRecordStorageException {
		for (final Log4jDeviceErrorHandler errorHandler : errorHandlers) {
			if (!errorHandler.isOk()) {
				throw new AuditRecordStorageException("A log4j device failed to log.");
			}
		}
	}
	
	@Override
	public AuditLogExportReport exportAuditLogs(AuthenticationToken arg0,
			CryptoToken arg1, Date arg2, boolean arg3,
			Map<String, Object> arg4, Properties arg5,
			Class<? extends AuditExporter> arg6)
			throws AuditLogExporterException {
		throw new UnsupportedOperationException(UNSUPPORTED);
	}

	@Override
	public List<? extends AuditLogEntry> selectAuditLogs(
			AuthenticationToken arg0, int arg1, int arg2, QueryCriteria arg3,
			Properties arg4) {
		throw new UnsupportedOperationException(UNSUPPORTED);
	}

	@Override
	public AuditLogValidationReport verifyLogsIntegrity(
			AuthenticationToken arg0, Date arg1, Properties arg2)
			throws AuditLogValidatorException {
		throw new UnsupportedOperationException(UNSUPPORTED);
	}

	@Override
	public void log(TrustedTime trustedTime, EventType eventType, EventStatus eventStatus,
			ModuleType moduleType, ServiceType service, String authToken, String customId,
			String searchDetail1, String searchDetail2, Map<String, Object> additionalDetails, Properties properties)
			throws AuditRecordStorageException {
		final StringBuilder str = new StringBuilder();	
		str.append("EVENT: ").append(eventType.toString()).append("; ")
		.append("MODULE: ").append(moduleType.toString()).append("; ")
		.append("CUSTOM_ID: ").append(customId).append("; ");
		
		for (Map.Entry<String, Object> entry : additionalDetails.entrySet()) {
			str.append(entry.getKey());
		 	str.append(": ");
		 	str.append(entry.getValue());
		 	str.append("; ");
		}
		
		// Last thing: add time for logging
		str.append(IWorkerLogger.LOG_REPLY_TIME);
		str.append(":");
		str.append(trustedTime.getTime().getTime());
		
		// Do log
		LOG.info(str.toString());
		assertNoErrors();
	}

	@Override
	public boolean isSupportingQueries() {
		return false;
	}

	@Override
	public void prepareReset() throws AuditLogResetException {
		// No action required
		
	}

	@Override
	public void reset() throws AuditLogResetException {
		// No action required
		
	}

	@Override
	public void setEjbs(Map<Class<?>, ?> arg0) {
		// Does not use any beans
	}

}
