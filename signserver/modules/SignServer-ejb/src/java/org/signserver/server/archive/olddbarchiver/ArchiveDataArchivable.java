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
package org.signserver.server.archive.olddbarchiver;

import org.signserver.common.ArchiveData;
import org.signserver.server.archive.AbstractArchivable;

/**
 * Adapter for the old ArchiveData to comply with the new Archiving API.
 * Holds the archiveId and archiveData object.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class ArchiveDataArchivable extends AbstractArchivable {

    /** Content type for this Archivable. */
    public static final String ARCHIVEDATA = "ARCHIVEDATA";

    private ArchiveData archiveData;

    public ArchiveDataArchivable(final String archiveId, 
            final ArchiveData archiveData, final String type,
            final String contentType) {
        super(type, archiveId, contentType);
        this.archiveData = archiveData;
    }

    public ArchiveDataArchivable(final String archiveId,
            final ArchiveData archiveData, final String type) {
        this(archiveId, archiveData, type, ARCHIVEDATA);
    }

    @Override
    public byte[] getContentEncoded() {
        return archiveData.getData();
    }

    public ArchiveData getArchiveData() {
        return archiveData;
    }

}
