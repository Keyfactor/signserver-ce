// XXX: Extracted from QueryArchiveCommand in AdminCLI. Should be refactored to
// common code
// See also AuditLogFields
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
import org.signserver.common.ArchiveMetadata;

/**
 *
 * @author user
 */
public class ArchiveFields {
    /** Option strings */
    public static final String QUERY = "query";
    public static final String FROM = "from";
    public static final String LIMIT = "limit";
    public static final String CRITERIA = "criteria";
    public static final String HEADER = "header";
 
    /** The command line options */
    public static final Set<String> intFields;
    public static final Set<String> dateFields;
    public static final Set<RelationalOperator> noArgOps;
    public static final Set<String> allowedFields;

    static {
        
        intFields = new HashSet<>();
        intFields.add(ArchiveMetadata.SIGNER_ID);
        
        dateFields = new HashSet<>();
        dateFields.add(ArchiveMetadata.TIME);
        
        noArgOps = new HashSet<>();
        noArgOps.add(RelationalOperator.NULL);
        noArgOps.add(RelationalOperator.NOTNULL);
     
        allowedFields = new HashSet<>();
        allowedFields.add(ArchiveMetadata.ARCHIVE_ID);
        allowedFields.add(ArchiveMetadata.REQUEST_CERT_SERIAL_NUMBER);
        allowedFields.add(ArchiveMetadata.REQUEST_IP);
        allowedFields.add(ArchiveMetadata.REQUEST_ISSUER_DN);
        allowedFields.add(ArchiveMetadata.SIGNER_ID);
        allowedFields.add(ArchiveMetadata.TIME);
        allowedFields.add(ArchiveMetadata.TYPE);
        allowedFields.add(ArchiveMetadata.UNIQUE_ID);
        
    }
}
