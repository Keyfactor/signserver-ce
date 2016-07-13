/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
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
 * The file is not removed.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class FileReadableData extends CloseableReadableData {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(FileReadableData.class);
    
    private final File file;

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
