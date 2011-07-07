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
 * Abstract Archivable. Provides default implementation for some boiler plate 
 * parts of an Archivable.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class AbstractArchivable implements Archivable {

    private String type;
    private String contentType;

    /**
     * Constructor taking a type and contentType.
     * @param type The type of Archivable this is.
     * @param contentType The MIME type of the content or similar.
     * @see Archivable#TYPE_REQUEST
     * @see Archivable#TYPE_RESPONSE
     */
    public AbstractArchivable(final String type, final String contentType) {
        this.type = type;
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

}
