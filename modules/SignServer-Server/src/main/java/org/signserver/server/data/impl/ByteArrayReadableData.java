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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;

/**
 * CloseableReadableData created from a byte array.
 * 
 * Create the instance in try-with-resource or manually call close().
 * The backing temporary file (if one) is removed when the instance is closed.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class ByteArrayReadableData extends CloseableReadableData {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ByteArrayReadableData.class);
    
    private final byte[] data;
    private final File repository;
    private File file;
    
    public ByteArrayReadableData(byte[] data, File repository) {
        this.data = data;
        this.repository = repository;
    }
    
    @Override
    public long getLength() {
        return data.length;
    }

    @Override
    public byte[] getAsByteArray() {
        return data;
    }
    
    @Override
    public boolean isFile() {
        return false;
    }

    @Override
    public File getAsFile() throws IOException {
        if (file == null) {
            // Write out the data to the file
            file = File.createTempFile("signserver-upload", ".tmp", repository);
            FileUtils.writeByteArrayToFile(file, data);
        }
        return file;
    }

    @Override
    public InputStream getAsInputStream() throws IOException {
        return register(new ByteArrayInputStream(data));
    }

    @Override
    public void close() throws IOException {
        // Close resources
        super.close();
        
        // Remove the file
        removeFile();
    }

    private void removeFile() throws IOException {
        if (file != null) {
            final boolean existed = Files.deleteIfExists(file.toPath());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Temporary file was " + file.getAbsolutePath() + (existed ? " removed" : " not removed as it did not exist"));
            }
        }
    }
    
}
