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

import java.io.IOException;
import org.signserver.common.data.ReadableData;

/**
 * Default Archivable with support for large files.
 * The old default Archivable implementation is now called ByteArrayArchivable.
 *
 * @author Markus Kilås
 * @version $Id$
 * @see ByteArrayArchivable
 */
public class DefaultArchivable extends AbstractArchivable {

    private static final long serialVersionUID = 0L;

    /** The default content-type. */
    private static final String APPLICATION_OCTET_STREAM 
            = "application/octet-stream";

    /** The data. */
    private transient ReadableData data; // Don't serialize the data. Let it stay a server side.

    /**
     * Creates an instance of DefaultArchivable with the given type, data and  
     * archive ID
     * @param type The type of Archivable.
     * @param data The data to archive.
     * @param archiveId Some ID of the transaction
     * @see Archivable#TYPE_REQUEST
     * @see Archivable#TYPE_RESPONSE
     */
    public DefaultArchivable(final String type, final ReadableData data, final String archiveId) {
        this(type, APPLICATION_OCTET_STREAM, data, archiveId);
    }

    /** Creates an instance of DefaultArchivable with the given type, 
     * content-type, data and archive ID.
     * @param type The type of Archivable.
     * @param archiveId Some ID of the transaction
     * @param contentType The content-type of the data.
     * @param data The data to archive.
     * @see Archivable#TYPE_REQUEST
     * @see Archivable#TYPE_RESPONSE
     */
    public DefaultArchivable(final String type, 
            final String contentType, final ReadableData data, final String archiveId) {
        super(type, archiveId, contentType);
        this.data = data;
    }

    @Override
    public byte[] getContentEncoded() {
        try {
            return data.getAsByteArray();
        } catch (IOException ex) {
            throw new IllegalStateException("Archive data unavailable: " + ex.getLocalizedMessage(), ex);
        }
    }

}
