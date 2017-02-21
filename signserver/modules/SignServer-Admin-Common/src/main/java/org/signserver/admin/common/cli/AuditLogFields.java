// XXX: Extracted from AuditLogCommand in AdminCLI. Should be refactored to
// common code
// See also ArchiveFields
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.admin.common.cli;

import java.util.HashSet;
import java.util.Set;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.util.query.elems.RelationalOperator;

/**
 *
 * @author user
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
