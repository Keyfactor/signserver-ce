/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.data.impl;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.WritableData;

/**
 * TODO: document.
 * 
 * Create the instance in try-with-resource or manually call close().
 * The backing temporary file (if one) is removed when the instance is closed.
 * @author user
 */
public class TemporarlyWritableData extends CloseableWritableData {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TemporarlyWritableData.class);
    
    private final boolean defaultToDisk;
    
    // Write
    private OutputStream outputStream;
    
    // Storage
    private File responseFile;
    private ByteArrayOutputStream inMemoryOutputStream;
    private byte[] data;

    // State
    private boolean noMoreWrite;

    public TemporarlyWritableData(boolean defaultToDisk) {
        this.defaultToDisk = defaultToDisk;
    }
    
    @Override
    public OutputStream getAsOutputStream() throws IOException {
        if (defaultToDisk) {
            return getAsFileOutputStream();
        } else {
            return getAsInMemoryOutputStream();
        }
    }

    @Override
    public OutputStream getAsFileOutputStream() throws IOException { // XXX duplicate/confusing
        ensureValid();
        if (outputStream == null) {
            if (responseFile == null) {
                responseFile = File.createTempFile("response_", ".tmp", new File(System.getProperty("java.io.tmpdir"))); //new File("/home/user/tmp/signserver/")); // TODO: configurable path
            }
            outputStream = register(new FileOutputStream(responseFile));
        }
        return outputStream;
    }
    
    @Override
    public OutputStream getAsInMemoryOutputStream() { // XXX duplicate/confusing
        if (noMoreWrite) {
            throw new IllegalStateException("Can not write response data after starting reading it");
        }
        if (outputStream == null) {
            inMemoryOutputStream = new ByteArrayOutputStream();
            outputStream = inMemoryOutputStream;
        }
        return outputStream;
    }
    
    @Override
    public File getAsFile() throws IOException { // XXX duplicate/confusing
        if (noMoreWrite) {
            throw new IllegalStateException("Can not write response data after starting reading it");
        }
        if (responseFile == null) {
            responseFile = File.createTempFile("response_", ".tmp", new File("/home/user/tmp/signserver/")); // TODO: configurable path
        }
        return responseFile;
    }
    
    private void ensureValid() {
        if (noMoreWrite) {
            throw new IllegalStateException("Output stream/file can only be obtained once");
        }
    }
    
    
    //////////////

    @Override
    public ReadableData toReadableData() {
        return new ReadableData() {
            @Override
            public byte[] getAsByteArray() throws IOException {
                noMoreWrite = true;
                if (data != null) {
                    return data;
                } else if (inMemoryOutputStream != null) {
                    data = inMemoryOutputStream.toByteArray();
                } else {
                    data = FileUtils.readFileToByteArray(responseFile);
                }
                return data;
            }

            @Override
            public InputStream getAsInputStream() throws IOException {
                noMoreWrite = true;
                final InputStream result;
                if (responseFile != null) {
                    // XXX was the file all written out, ie. we need to out.close and fd.sync() ?
                    result = register(new BufferedInputStream(new FileInputStream(responseFile)));
                } else if (inMemoryOutputStream != null) {
                    data = inMemoryOutputStream.toByteArray();
                    result = new ByteArrayInputStream(data);
                } else {
                    if (data == null) {
                        data = FileUtils.readFileToByteArray(responseFile);
                    }
                    result = new ByteArrayInputStream(data);
                }
                return result;
            }

            @Override
            public File getAsFile() throws IOException {
                if (responseFile != null) {
                    return responseFile;
                } else {
                    responseFile = File.createTempFile("response_", ".tmp", new File("/home/user/tmp/signserver/")); // TODO: configurable path
                    FileUtils.writeByteArrayToFile(responseFile, inMemoryOutputStream.toByteArray());
                }
                return responseFile;
            }

            @Override
            public long getLength() {
                noMoreWrite = true;
                if (responseFile != null) {
                    return responseFile.length();
                } else {
                    return inMemoryOutputStream.size();
                }
            }

            @Override
            public boolean isFile() {
                return responseFile != null;
            }
            
        };
    }

    @Override
    public void close() throws IOException {
        // Close resources
        super.close();
        inMemoryOutputStream = null;
        data = null;
        
        // Remove the file
        removeFile();
    }

    private void removeFile() throws IOException {
        if (responseFile != null) {
            final boolean existed = Files.deleteIfExists(responseFile.toPath());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Temporary file was " + responseFile.getAbsolutePath() + (existed ? " removed" : " not removed as it did not exist"));
            }
        }
    }

}
