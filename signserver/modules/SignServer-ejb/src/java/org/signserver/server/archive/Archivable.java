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
 * An Archivable is an item that can be archived by an Archiver.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface Archivable {
    
    /** The item is the request. */
    String TYPE_REQUEST = "REQUEST";
    
    /** The item is the response. */
    String TYPE_RESPONSE = "RESPONSE";

    /**
     * @return The type of this Archivable. TYPE_REQUEST, TYPE_RESPONSE or other.
     */
    String getType();
    
    /**
     * @return  The type of the content for instance expressed as a MIME type.
     */
    String getContentType();
    
    /**
     * @return The binary serialization of the content.
     */
    byte[] getContentEncoded();
}
