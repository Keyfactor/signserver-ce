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
package org.signserver.admin.gui;

import java.util.HashMap;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;

/**
 * Representation of an relational operator.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AuditlogOperator {
    
    private static final AuditlogOperator[] COLUMNS =  {
        new AuditlogOperator(AuditRecordData.FIELD_ADDITIONAL_DETAILS, "Details"),
        new AuditlogOperator(AuditRecordData.FIELD_AUTHENTICATION_TOKEN, "Administrator"),
        new AuditlogOperator(AuditRecordData.FIELD_CUSTOM_ID, "Certificate Authority"),
        new AuditlogOperator(AuditRecordData.FIELD_EVENTSTATUS, "Outcome"),
        new AuditlogOperator(AuditRecordData.FIELD_EVENTTYPE, "Event"),
        new AuditlogOperator(AuditRecordData.FIELD_MODULE, "Module"),
        new AuditlogOperator(AuditRecordData.FIELD_NODEID, "Node"),
        new AuditlogOperator(AuditRecordData.FIELD_SEARCHABLE_DETAIL1, "Certificate"),
        new AuditlogOperator(AuditRecordData.FIELD_SEARCHABLE_DETAIL2, "Username"),
        new AuditlogOperator(AuditRecordData.FIELD_SERVICE, "Service"),
        new AuditlogOperator(AuditRecordData.FIELD_SEQUENCENUMBER, "Sequence Number"),
        new AuditlogOperator(AuditRecordData.FIELD_TIMESTAMP, "Time")
    };
    
    private static final HashMap<String, String> DESCRIPTIONS = new HashMap<String, String>();
    
    static {
        for (AuditlogOperator column : COLUMNS) {
            DESCRIPTIONS.put(column.getName(), column.getDescription());
        }
    }
    
    private String name;
    private String description;

    public AuditlogOperator(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return description + " (" + name + ")";
    }

    public static AuditlogOperator[] getColumns() {
        return COLUMNS;
    }
    
    public static String getDescription(final String name) {
        return DESCRIPTIONS.get(name);
    }
    
}
