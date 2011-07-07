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
 * Default Archivable holding any byte[].
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class DefaultArchivable extends AbstractArchivable {

    private static final String APPLICATION_OCTET_STREAM 
            = "application/octet-stream";

    private byte[] bytes;

    public DefaultArchivable(final String type, final byte[] bytes) {
        this(type, APPLICATION_OCTET_STREAM, bytes);
    }

    public DefaultArchivable(final String type, final String contentType,
            final byte[] bytes) {
        super(type, contentType);
        this.bytes = bytes;
    }

    public byte[] getContentEncoded() {
        return bytes;
    }

}
