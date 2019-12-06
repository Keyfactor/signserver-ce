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
package org.signserver.server.archive;

import java.io.Serializable;

/**
 * Abstract Archivable. Provides default implementation for some boiler plate 
 * parts of an Archivable.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class AbstractArchivable implements Archivable, Serializable {

    private static final long serialVersionUID = 0L;

    private final String type;
    
    /** ID of the transaction. */
    private final String archiveId;
    
    private final String contentType;

    /**
     * Constructor taking a type and contentType.
     * 
     * @param type The type of Archivable this is.
     * @param archiveId ID of archivable
     * @param contentType The MIME type of the content or similar.
     * @see Archivable#TYPE_REQUEST
     * @see Archivable#TYPE_RESPONSE
     * @since SignServer 3.3
     */
    public AbstractArchivable(final String type, final String archiveId, final String contentType) {
        this.type = type;
        this.archiveId = archiveId;
        this.contentType = contentType;
    }

    @Override
    public String getType() {
        return type;
    }

    @Override
    public String getContentType() {
        return contentType;
    }

    @Override
    public String getArchiveId() {
        return archiveId;
    }
    
}
