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

import java.util.Arrays;
import java.util.Collection;
import org.signserver.common.ArchiveMetadata;

/**
 * Representation of an archive search result column column with name and
 * description.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public enum ArchiveColumn implements QueryColumn {

    ARCHIVE_ID(ArchiveMetadata.ARCHIVE_ID, "Archive ID", Type.TEXT),
    REQUEST_CERT_SERIAL_NUMBER(ArchiveMetadata.REQUEST_CERT_SERIAL_NUMBER,
            "Certificate Serial Number", Type.TEXT),
    REQUEST_CERT_ISSUER_DN(ArchiveMetadata.REQUEST_ISSUER_DN,
            "Issuer DN", Type.TEXT),
    REQUEST_IP(ArchiveMetadata.REQUEST_IP, "IP Address", Type.TEXT),
    SIGNER_ID(ArchiveMetadata.SIGNER_ID, "Signer ID", Type.NUMBER),
    TIME(ArchiveMetadata.TIME, "Time", Type.TIME),
    TYPE(ArchiveMetadata.TYPE, "Type", Type.TYPE) {
        @Override
        public Collection<String> getTypeValues() {
            return Arrays.asList(ArchiveMetadata.TYPE_NAMES);
        }
        
        @Override
        public String translateConditionValue(final String value) {
            return Integer.toString(ArchiveMetadata.translateTypeName(value));
        }
    },
    UNIQUE_ID(ArchiveMetadata.UNIQUE_ID, "Unique ID", Type.TEXT);
    
    private final String name;
    private final String description;
    private final Type type;
    
    private ArchiveColumn(final String name, final String description,
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
    public String translateConditionValue(final String value) {
        return value;
    }
    
    @Override
    public String toString() {
        return description + " (" + name + ")";
    }
}
