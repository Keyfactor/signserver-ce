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
package org.signserver.server.data.impl;

import java.io.File;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.signserver.common.data.ReadableData;

/**
 * Factory for readable and writable data objects.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface DataFactory {

    /**
     * Create a readable data implementation from the provided byte array.
     * @param data to use
     * @param maxSize to allow for data
     * @param repository to store the data as file in (if requested)
     * @return a new readable data instance
     * @throws FileUploadException in case data.length > maxSize
     */
    CloseableReadableData createReadableData(byte[] data, long maxSize, File repository) throws FileUploadException;
    
    /**
     * Create a readable data implementation from the provided FileItem.
     * @param item data to use
     * @param repository to store the data as file in (if requested)
     * @return a new readable data instance
     */
    CloseableReadableData createReadableData(FileItem item, File repository);

    /**
     * Create a writable data implementation with settings from the provided
     * readable data.
     * @param readableData with settings for how to create the writable data
     * @param repository to store the data as file in (if requested)
     * @return a new writable data instance
     */
    CloseableWritableData createWritableData(ReadableData readableData, File repository);
    
    /**
     * Create a writable data implementation while hinting if it should be on
     * disk or not by default.
     * @param defaultToDisk if it should be backed by a file
     * @param repository to store the data as file in (if requested)
     * @return a new readable data instance
     */
    CloseableWritableData createWritableData(boolean defaultToDisk, File repository);
}
