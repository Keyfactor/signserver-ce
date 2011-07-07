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
 * Abstract Archivable.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class AbstractArchivable implements Archivable {

    private String type;
    private String contentType;

    public AbstractArchivable(final String type, final String contentType) {
        this.type = type;
        this.contentType = contentType;
    }

    public String getType() {
        return type;
    }

    public String getContentType() {
        return contentType;
    }

}
