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
package org.signserver.admin.web;

import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import org.apache.commons.lang.time.FastDateFormat;
import org.cesecore.audit.AuditLogEntry;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class WebAuditLogEntry {

    private static final FastDateFormat FDF = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ssZ");

    private final AuditLogEntry delegate;
    private final Long sequenceNumber;
    private final String time;
    private final String outcome;
    private final String event;
    private final String module;
    private final String service;
    private final String adminSubject;
    private final String adminSerialNumber;
    private final String adminIssuer;
    private final String workerID;
    private final String node;
    private final String details;

    static WebAuditLogEntry fromAuditLogEntry(AuditLogEntry entry) {
        return new WebAuditLogEntry(
                entry,
                entry.getSequenceNumber(),
                FDF.format(new Date((long) entry.getTimeStamp())),
                String.valueOf(entry.getEventStatusValue()),
                String.valueOf(entry.getEventTypeValue()),
                String.valueOf(entry.getModuleTypeValue()),
                String.valueOf(entry.getServiceTypeValue()),
                entry.getAuthToken(),
                entry.getSearchDetail1(),
                entry.getCustomId(),
                entry.getSearchDetail2(),
                entry.getNodeId(),
                toFirstLineString(entry.getMapAdditionalDetails()));
    }

    public WebAuditLogEntry(AuditLogEntry delegate, Long sequenceNumber, String time, String outcome, String event, String module, String service, String adminSubject, String adminSerialNumber, String adminIssuer, String workerID, String node, String details) {
        this.delegate = delegate;
        this.sequenceNumber = sequenceNumber;
        this.time = time;
        this.outcome = outcome;
        this.event = event;
        this.module = module;
        this.service = service;
        this.adminSubject = adminSubject;
        this.adminSerialNumber = adminSerialNumber;
        this.adminIssuer = adminIssuer;
        this.workerID = workerID;
        this.node = node;
        this.details = details;
    }

    private static String toFirstLineString(Map<String, Object> details) {
        final StringBuilder buff = new StringBuilder();
        final Iterator<Map.Entry<String, Object>> it = details.entrySet().iterator();
        if (it.hasNext()) {
            final Map.Entry<String, Object> entry = it.next();
            buff.append(entry.getKey()).append("=").append(entry.getValue());
            if (it.hasNext()) {
                buff.append("...");
            }
        }
        return buff.toString();
    }

    public Long getSequenceNumber() {
        return sequenceNumber;
    }

    public String getTime() {
        return time;
    }

    public String getOutcome() {
        return outcome;
    }

    public String getEvent() {
        return event;
    }

    public String getModule() {
        return module;
    }

    public String getService() {
        return service;
    }

    public String getAdminSubject() {
        return adminSubject;
    }

    public String getAdminSerialNumber() {
        return adminSerialNumber;
    }

    public String getAdminIssuer() {
        return adminIssuer;
    }

    public String getWorkerID() {
        return workerID;
    }

    public String getNode() {
        return node;
    }

    public String getDetails() {
        return details;
    }

    public String getFullDetails() {
        final StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Object> ent : delegate.getMapAdditionalDetails().entrySet()) {
            sb.append(ent.getKey()).append("=").append(ent.getValue()).append("\n");
        }

        return sb.toString();
    }

}
