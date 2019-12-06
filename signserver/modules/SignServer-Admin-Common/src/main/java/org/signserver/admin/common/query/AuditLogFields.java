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

import java.util.HashSet;
import java.util.Set;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.util.query.elems.RelationalOperator;

/**
 * Constants for querying the audit log from CLI and web.
 *
 * @author Marcus Lundblad
 * @author Markus Kilås
 */
public class AuditLogFields {

    /** Option strings */
    public static final String QUERY = "query";
    public static final String FROM = "from";
    public static final String LIMIT = "limit";
    public static final String CRITERIA = "criteria";
    public static final String HEADER = "header";
 
    /** The command line options */
    public static final Set<String> LONG_FIELDS;
    public static final Set<String> DATE_FIELDS;
    public static final Set<RelationalOperator> NO_ARG_OPS;
    public static final Set<String> ALLOWED_FIELDS;
    
    public static final String ERR_DB_PROTECTION_FAILED = "Database protection failed within the selected interval: ";
    public static final String ERR_RELOAD_FAILED = "Reload failed within the selected interval: ";

    static {
        
        LONG_FIELDS = new HashSet<>();
        LONG_FIELDS.add(AuditRecordData.FIELD_SEQUENCENUMBER);
        
        DATE_FIELDS = new HashSet<>();
        DATE_FIELDS.add(AuditRecordData.FIELD_TIMESTAMP);
        
        NO_ARG_OPS = new HashSet<>();
        NO_ARG_OPS.add(RelationalOperator.NULL);
        NO_ARG_OPS.add(RelationalOperator.NOTNULL);
        
        // allowed fields from CESeCore
        // TODO: should maybe define this in CESeCore?
        ALLOWED_FIELDS = new HashSet<>();
        ALLOWED_FIELDS.add(AuditRecordData.FIELD_ADDITIONAL_DETAILS);
        ALLOWED_FIELDS.add(AuditRecordData.FIELD_AUTHENTICATION_TOKEN);
        ALLOWED_FIELDS.add(AuditRecordData.FIELD_CUSTOM_ID);
        ALLOWED_FIELDS.add(AuditRecordData.FIELD_EVENTSTATUS);
        ALLOWED_FIELDS.add(AuditRecordData.FIELD_EVENTTYPE);
        ALLOWED_FIELDS.add(AuditRecordData.FIELD_MODULE);
        ALLOWED_FIELDS.add(AuditRecordData.FIELD_NODEID);
        ALLOWED_FIELDS.add(AuditRecordData.FIELD_SEARCHABLE_DETAIL1);
        ALLOWED_FIELDS.add(AuditRecordData.FIELD_SEARCHABLE_DETAIL2);
        ALLOWED_FIELDS.add(AuditRecordData.FIELD_SERVICE);
        ALLOWED_FIELDS.add(AuditRecordData.FIELD_SEQUENCENUMBER);
        ALLOWED_FIELDS.add(AuditRecordData.FIELD_TIMESTAMP);
        
    }
}
