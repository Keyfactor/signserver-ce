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

import java.util.Arrays;
import java.util.Collection;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.ArchiveMetadata;
import org.signserver.server.archive.Archivable;

/**
 * Representation of an archive search result column column with name and description.
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
            return Arrays.asList(Archivable.TYPE_REQUEST, Archivable.TYPE_RESPONSE);
        }
        
        @Override
        public String translateConditionValue(final String value) {
            if (Archivable.TYPE_REQUEST.equals(value)) {
                return Integer.toString(ArchiveDataVO.TYPE_REQUEST);
            } else if (Archivable.TYPE_RESPONSE.equals(value)) {
                return Integer.toString(ArchiveDataVO.TYPE_RESPONSE);
            } else {
                throw new IllegalArgumentException("Unknown TYPE value: " + value);
            }
        }
    };
    
    private String name;
    private String description;
    private Type type;
    
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
}
