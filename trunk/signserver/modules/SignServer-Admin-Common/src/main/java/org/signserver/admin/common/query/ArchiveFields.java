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
import org.cesecore.util.query.elems.RelationalOperator;
import org.signserver.common.ArchiveMetadata;

/**
 * Constants for querying the archive from CLI and web.
 *
 * @author Marcus Lundblad
 * @author Markus Kilås
 */
public class ArchiveFields {

    /** Option strings */
    public static final String QUERY = "query";
    public static final String FROM = "from";
    public static final String LIMIT = "limit";
    public static final String CRITERIA = "criteria";
    public static final String HEADER = "header";
 
    /** The command line options */
    public static final Set<String> INT_FIELDS;
    public static final Set<String> DATE_FIELDS;
    public static final Set<RelationalOperator> NO_ARG_OPS;
    public static final Set<String> ALLOWED_FIELDS;

    static {
        
        INT_FIELDS = new HashSet<>();
        INT_FIELDS.add(ArchiveMetadata.SIGNER_ID);
        
        DATE_FIELDS = new HashSet<>();
        DATE_FIELDS.add(ArchiveMetadata.TIME);
        
        NO_ARG_OPS = new HashSet<>();
        NO_ARG_OPS.add(RelationalOperator.NULL);
        NO_ARG_OPS.add(RelationalOperator.NOTNULL);
     
        ALLOWED_FIELDS = new HashSet<>();
        ALLOWED_FIELDS.add(ArchiveMetadata.ARCHIVE_ID);
        ALLOWED_FIELDS.add(ArchiveMetadata.REQUEST_CERT_SERIAL_NUMBER);
        ALLOWED_FIELDS.add(ArchiveMetadata.REQUEST_IP);
        ALLOWED_FIELDS.add(ArchiveMetadata.REQUEST_ISSUER_DN);
        ALLOWED_FIELDS.add(ArchiveMetadata.SIGNER_ID);
        ALLOWED_FIELDS.add(ArchiveMetadata.TIME);
        ALLOWED_FIELDS.add(ArchiveMetadata.TYPE);
        ALLOWED_FIELDS.add(ArchiveMetadata.UNIQUE_ID);
        
    }
}
