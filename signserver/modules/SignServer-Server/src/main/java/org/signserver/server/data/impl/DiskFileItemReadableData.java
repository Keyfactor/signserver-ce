/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.data.impl;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import org.apache.commons.fileupload.disk.DiskFileItem;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;

/**
 * TODO: Document.
 * 
 * Create the instance in try-with-resource or manually call close().
 * The backing temporary file (if one) is removed when the instance is closed.
 * 
 * @author user
 */
public class DiskFileItemReadableData extends CloseableReadableData {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DiskFileItemReadableData.class);
    
    private final DiskFileItem fileItem;
    private File file;
    
    public DiskFileItemReadableData(DiskFileItem fileItem) {
        this.fileItem = fileItem;
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
                // Create a temp file
                throw new UnsupportedOperationException("getAsFile for fileItem without store location not yet implemented, DSS-1180");
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
