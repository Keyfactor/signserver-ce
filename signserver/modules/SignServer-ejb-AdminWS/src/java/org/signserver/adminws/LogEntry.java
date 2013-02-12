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
package org.signserver.adminws;

import java.util.HashMap;
import java.util.Map;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.enums.EventStatus;

/**
 * Holder for an log entry.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class LogEntry {
    
    private Long timeStamp;
    private String eventType;
    private EventStatus eventStatus;
    private String authToken;
    private String serviceType;
    private String moduleType;
    private String customId;
    private String searchDetail1;
    private String searchDetail2;
    private Map<String, String> additionalDetails;
    private Long sequenceNumber;
    private String nodeId;

    public LogEntry() {
    }

    public LogEntry(Long timeStamp, String eventType, EventStatus eventStatus, String authToken, String serviceType, String moduleType, String customId, String searchDetail1, String searchDetail2, Map<String, String> additionalDetails, Long sequenceNumber, String nodeId) {
        this.timeStamp = timeStamp;
        this.eventType = eventType;
        this.eventStatus = eventStatus;
        this.authToken = authToken;
        this.serviceType = serviceType;
        this.moduleType = moduleType;
        this.customId = customId;
        this.searchDetail1 = searchDetail1;
        this.searchDetail2 = searchDetail2;
        this.additionalDetails = additionalDetails;
        this.sequenceNumber = sequenceNumber;
        this.nodeId = nodeId;
    }
    
    public static LogEntry fromAuditLogEntry(final AuditLogEntry src) {
        HashMap<String, String> additionalDetails = new HashMap<String, String>();
        for (Map.Entry<String, Object> entry : src.getMapAdditionalDetails().entrySet()) {
            if (entry.getKey() != null) {
                additionalDetails.put(entry.getKey(), entry.getValue() == null ? null : entry.getValue().toString());
            }
        }
        return new LogEntry(src.getTimeStamp(), src.getEventTypeValue().toString(), src.getEventStatusValue(), src.getAuthToken(), src.getServiceTypeValue().toString(), src.getModuleTypeValue().toString(), src.getCustomId(), src.getSearchDetail1(), src.getSearchDetail2(), additionalDetails, src.getSequenceNumber(), src.getNodeId());
    }

    public Long getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(Long timeStamp) {
        this.timeStamp = timeStamp;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public EventStatus getEventStatus() {
        return eventStatus;
    }

    public void setEventStatus(EventStatus eventStatus) {
        this.eventStatus = eventStatus;
    }

    public String getAuthToken() {
        return authToken;
    }

    public void setAuthToken(String authToken) {
        this.authToken = authToken;
    }

    public String getServiceType() {
        return serviceType;
    }

    public void setServiceType(String serviceType) {
        this.serviceType = serviceType;
    }

    public String getModuleType() {
        return moduleType;
    }

    public void setModuleType(String moduleType) {
        this.moduleType = moduleType;
    }

    public String getCustomId() {
        return customId;
    }

    public void setCustomId(String customId) {
        this.customId = customId;
    }

    public String getSearchDetail1() {
        return searchDetail1;
    }

    public void setSearchDetail1(String searchDetail1) {
        this.searchDetail1 = searchDetail1;
    }

    public String getSearchDetail2() {
        return searchDetail2;
    }

    public void setSearchDetail2(String searchDetail2) {
        this.searchDetail2 = searchDetail2;
    }

    public Map<String, String> getAdditionalDetails() {
        return additionalDetails;
    }

    public void setAdditionalDetails(Map<String, String> additionalDetails) {
        this.additionalDetails = additionalDetails;
    }

    public Long getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(Long sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public String getNodeId() {
        return nodeId;
    }

    public void setNodeId(String nodeId) {
        this.nodeId = nodeId;
    }

}
