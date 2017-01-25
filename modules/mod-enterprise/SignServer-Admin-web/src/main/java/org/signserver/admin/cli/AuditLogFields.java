// XXX: Extracted from AuditLogCommand in AdminCLI. Should be refactored to
// common code
// See also ArchiveFields
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.admin.cli;

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
    public static final Set<String> longFields;
    public static final Set<String> dateFields;
    public static final Set<RelationalOperator> noArgOps;
    public static final Set<String> allowedFields;

    static {
        
        longFields = new HashSet<>();
        longFields.add(AuditRecordData.FIELD_SEQUENCENUMBER);
        
        dateFields = new HashSet<>();
        dateFields.add(AuditRecordData.FIELD_TIMESTAMP);
        
        noArgOps = new HashSet<>();
        noArgOps.add(RelationalOperator.NULL);
        noArgOps.add(RelationalOperator.NOTNULL);
        
        // allowed fields from CESeCore
        // TODO: should maybe define this in CESeCore?
        allowedFields = new HashSet<>();
        allowedFields.add(AuditRecordData.FIELD_ADDITIONAL_DETAILS);
        allowedFields.add(AuditRecordData.FIELD_AUTHENTICATION_TOKEN);
        allowedFields.add(AuditRecordData.FIELD_CUSTOM_ID);
        allowedFields.add(AuditRecordData.FIELD_EVENTSTATUS);
        allowedFields.add(AuditRecordData.FIELD_EVENTTYPE);
        allowedFields.add(AuditRecordData.FIELD_MODULE);
        allowedFields.add(AuditRecordData.FIELD_NODEID);
        allowedFields.add(AuditRecordData.FIELD_SEARCHABLE_DETAIL1);
        allowedFields.add(AuditRecordData.FIELD_SEARCHABLE_DETAIL2);
        allowedFields.add(AuditRecordData.FIELD_SERVICE);
        allowedFields.add(AuditRecordData.FIELD_SEQUENCENUMBER);
        allowedFields.add(AuditRecordData.FIELD_TIMESTAMP);
        
    }
}
