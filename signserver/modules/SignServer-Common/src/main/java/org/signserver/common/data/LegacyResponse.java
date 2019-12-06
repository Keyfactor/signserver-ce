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
package org.signserver.common.data;

import java.util.Collection;
import org.signserver.common.IArchivableProcessResponse;
import org.signserver.common.ProcessResponse;
import org.signserver.server.archive.Archivable;

/**
 * Data holder wrapping a legacy ProcessResponse.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class LegacyResponse extends Response implements IArchivableProcessResponse {

    private final ProcessResponse legacyResponse;
    private String archiveId;
    private Collection<? extends Archivable> archivables;

    public LegacyResponse(ProcessResponse legacyResponse) {
        this.legacyResponse = legacyResponse;
        if (legacyResponse instanceof IArchivableProcessResponse) {
            archiveId = ((IArchivableProcessResponse) legacyResponse).getArchiveId();
            archivables = ((IArchivableProcessResponse) legacyResponse).getArchivables();
        }
    }

    public ProcessResponse getLegacyResponse() {
        return legacyResponse;
    }

    @Override
    public String getArchiveId() {
        return archiveId;
    }

    @Override
    public Collection<? extends Archivable> getArchivables() {
        return archivables;
    }

}
