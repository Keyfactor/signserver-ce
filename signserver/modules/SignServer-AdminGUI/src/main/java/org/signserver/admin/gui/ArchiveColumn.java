/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.admin.gui;

import java.util.Arrays;
import java.util.Collection;
import org.signserver.common.ArchiveMetadata;
import org.signserver.server.archive.Archivable;

/**
 *
 * @author marcus
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
    
}
