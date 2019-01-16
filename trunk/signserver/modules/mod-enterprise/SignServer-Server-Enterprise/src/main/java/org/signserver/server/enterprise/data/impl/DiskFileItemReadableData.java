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
package org.signserver.server.enterprise.data.impl;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import org.apache.commons.fileupload.disk.DiskFileItem;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.signserver.server.data.impl.CloseableReadableData;

/**
 * CloseableReadableData backed by a DiskFileItem.
 * 
 * Create the instance in try-with-resource or manually call close().
 * The backing temporary file (if one) is removed when the instance is closed.
 * 
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class DiskFileItemReadableData extends CloseableReadableData {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DiskFileItemReadableData.class);
    
    private static final String FILE_PREFIX = "signserver-response_";
    private static final String FILE_SUFFIX = ".tmp";
    
    private final DiskFileItem fileItem;
    private final File repository;
    private File file;
    
    /**
     * Creates an instance of DiskFileItemReadableData using the provided
     * DiskFileItem and directory for storing temporary files.
     *
     * @param fileItem to back this ReadableData
     * @param repository to host any temporary file
     */
    public DiskFileItemReadableData(DiskFileItem fileItem, File repository) {
        this.fileItem = fileItem;
        this.repository = repository;
    }
    
    @Override
    public long getLength() {
        return fileItem.getSize();
    }

    @Override
    public byte[] getAsByteArray() {
        return fileItem.get();
    }
    
    @Override
    public boolean isFile() {
        return !fileItem.isInMemory();
    }

    @Override
    public File getAsFile() throws IOException {
        if (file == null) {
            // Get the file location
            file = fileItem.getStoreLocation();

            // Did not have a file location
            if (file == null) {
                file = File.createTempFile(FILE_PREFIX, FILE_SUFFIX, repository);
            }

            // Write out the data to the file    
            if (fileItem.isInMemory()) {
                FileUtils.writeByteArrayToFile(file, fileItem.get());
            }
        }
        return file;
    }

    @Override
    public InputStream getAsInputStream() throws IOException {
        return register(fileItem.getInputStream());
    }

    @Override
    public void close() throws IOException {
        // Close resources
        super.close();
        
        // Remove the file
        removeFile();
    }

    private void removeFile() throws IOException {
        if (fileItem != null) {
            fileItem.delete();
        }
        
        if (file != null) {
            final boolean existed = Files.deleteIfExists(file.toPath());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Temporary file was " + file.getAbsolutePath() + (existed ? " removed" : " not removed as it did not exist"));
            }
        }
    }
    
}
