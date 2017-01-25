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

/**
 * Archivable holding any byte[].
 * 
 * Note that it is preferably to the DefaultArchivable which supports large
 * files.
 *
 * @author Markus Kilås
 * @version $Id$
 * @see DefaultArchivable
 */
public class ByteArrayArchivable extends AbstractArchivable {

    /** The default content-type. */
    private static final String APPLICATION_OCTET_STREAM 
            = "application/octet-stream";

    /** The data. */
    private byte[] bytes;

    /**
     * Creates an instance of DefaultArchivable with the given type, data and  
     * archive ID
     * @param type The type of Archivable.
     * @param bytes The data to archive.
     * @param archiveId Some ID of the transaction
     * @see Archivable#TYPE_REQUEST
     * @see Archivable#TYPE_RESPONSE
     */
    public ByteArrayArchivable(final String type, final byte[] bytes, final String archiveId) {
        this(type, APPLICATION_OCTET_STREAM, bytes, archiveId);
    }

    /** Creates an instance of DefaultArchivable with the given type, 
     * content-type, data and archive ID.
     * @param type The type of Archivable.
     * @param archiveId Some ID of the transaction
     * @param contentType The content-type of the data.
     * @param bytes The data to archive.
     * @see Archivable#TYPE_REQUEST
     * @see Archivable#TYPE_RESPONSE
     */
    public ByteArrayArchivable(final String type, 
            final String contentType, final byte[] bytes, final String archiveId) {
        super(type, archiveId, contentType);
        this.bytes = bytes;
    }

    @Override
    public byte[] getContentEncoded() {
        return bytes;
    }

}
