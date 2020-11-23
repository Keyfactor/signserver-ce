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
package org.signserver.admin.common.query;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;

/**
 * Representation of an audit log column with name and description.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public enum AuditLogColumn implements QueryColumn {
    
    ADDITIONAL_DETAILS(AuditRecordData.FIELD_ADDITIONAL_DETAILS, "Details", Type.TEXT),
    AUTHENTICATION_TOKEN(AuditRecordData.FIELD_AUTHENTICATION_TOKEN, "Admin Subject", Type.TEXT),
    CUSTOM_ID(AuditRecordData.FIELD_CUSTOM_ID, "Admin Issuer", Type.TEXT),
    EVENTSTATUS(AuditRecordData.FIELD_EVENTSTATUS, "Outcome", Type.TYPE) {
        @Override
        public Collection<String> getTypeValues() {
            final List<String> values = new ArrayList<>();
            
            for (final EventStatus status : EventStatus.values()) {
                values.add(status.name());
            }
            
            return values;
        }
    },
    EVENTTYPE(AuditRecordData.FIELD_EVENTTYPE, "Event", Type.TEXT), 
    NODEID(AuditRecordData.FIELD_NODEID, "Node", Type.TEXT),
    SEARCHABLE_DETAIL1(AuditRecordData.FIELD_SEARCHABLE_DETAIL1, "Admin Serial Number", Type.TEXT),
    SEARCHABLE_DETAIL2(AuditRecordData.FIELD_SEARCHABLE_DETAIL2, "Worker ID", Type.TEXT),
    SERVICE(AuditRecordData.FIELD_SERVICE, "Service", Type.TEXT),
    SEQUENCENUMBER(AuditRecordData.FIELD_SEQUENCENUMBER, "Sequence Number", Type.NUMBER),
    TIMESTAMP(AuditRecordData.FIELD_TIMESTAMP, "Time", Type.TIME),
    MODULE(AuditRecordData.FIELD_MODULE, "Module",Type.TEXT);

    private final String name;
    private final String description;
    private final Type type;
    
    AuditLogColumn(final String name, final String description,
            final Type type) {
        this.name = name;
        this.description = description;
        this.type = type;
    }
    
    @Override
    public String getName() {
        return name;
    }
    
    @Override
    public String getDescription() {
        return description;
    }
    
    @Override
    public Type getType() {
        return type;
    }
    
    @Override
    public Collection<String> getTypeValues() throws IllegalArgumentException {
        throw new IllegalArgumentException("Not supported on column of type "
                + getName());
    }
    
    @Override
    public String toString() {
        return description + " (" + name + ")";
    }
    
    @Override
    public String translateConditionValue(final String value) {
        return value;
    }
}
