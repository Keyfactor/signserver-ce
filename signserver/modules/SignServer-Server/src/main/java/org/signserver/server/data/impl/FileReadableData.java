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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;

/**
 * ReadableData backed by a file.
 * Useful for unit tests.
 * Note: The file is not removed.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class FileReadableData extends CloseableReadableData {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(FileReadableData.class);
    
    private final File file;

    /**
     * Creates a ReadableData backed by the provided file.
     * The file will not be removed.
     * @param file that will back this instance
     */
    public FileReadableData(File file) {
        this.file = file;
    }
    
    @Override
    public long getLength() {
        return file.length();
    }

    @Override
    public byte[] getAsByteArray() {
        try {
            return FileUtils.readFileToByteArray(file);
        } catch (IOException ex) {
            LOG.error("Unable to read file " + file.getAbsolutePath(), ex);
            return null;
        }
    }
    
    @Override
    public boolean isFile() {
        return true;
    }

    @Override
    public File getAsFile() throws IOException {
        return file;
    }

    @Override
    public InputStream getAsInputStream() throws IOException {
        return register(new BufferedInputStream(new FileInputStream(file)));
    }

}
