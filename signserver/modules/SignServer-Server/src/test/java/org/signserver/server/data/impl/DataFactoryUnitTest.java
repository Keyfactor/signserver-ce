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
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import org.apache.commons.fileupload.FileUploadBase;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import static org.junit.Assert.*;
import org.signserver.common.data.ReadableData;

/**
 * Unit tests for the DataFactory.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class DataFactoryUnitTest {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DataFactoryUnitTest.class);
    
    private final File fileRepository = new UploadConfig().getRepository();

    private DataFactory createDataFactory() {
        return new DefaultDataFactory();
    }

    /**
     * Tests that a DataFactory can be created.
     * @throws Exception 
     */
    @Test
    public void testCreateDataFactory() throws Exception {
        DataFactory dataFactory = DataUtils.createDataFactory();
        assertNotNull("created instance", dataFactory);
    }

    /**
     * Tests the method DataFactory.createReadabeData(byte[],...).
     * @throws Exception 
     */
    @Test
    public void testDataFactoryCreateReadableData_byteArray() throws Exception {
        DataFactory dataFactory = createDataFactory();
        
        byte[] bytes = "abcdefghijklmn".getBytes(StandardCharsets.US_ASCII);
        int length = bytes.length;
        
        File file;
        try (CloseableReadableData readableData = dataFactory.createReadableData(bytes, 10000, fileRepository)) {
            // Check length
            assertEquals("length", length, readableData.getLength());
            
            // Not from file
            assertFalse("not file", readableData.isFile());
            
            // Can be read as byte array
            assertEquals("byte array", Hex.toHexString(bytes), Hex.toHexString(readableData.getAsByteArray()));
            
            // Can be read as stream
            assertEquals("stream", Hex.toHexString(bytes), Hex.toHexString(IOUtils.toByteArray(readableData.getAsInputStream())));
            
            // Can be read as file
            file = readableData.getAsFile();
            assertEquals("file", Hex.toHexString(bytes), Hex.toHexString(FileUtils.readFileToByteArray(file)));
        }
        // File removed (auto-closeable)
        assertFalse("file removed", file.exists());
    }

    /**
     * Tests that the method DataFactory.createReadabeData(byte[],...) throws
     * an Exception on too large data (+3000).
     * @throws Exception 
     */
    @Test(expected = FileUploadBase.SizeLimitExceededException.class)
    public void testDataFactoryCreateReadableData_byteArray_tooLarge3000() throws Exception {
        DataFactory dataFactory = createDataFactory();
        byte[] bytes = new byte[13000];
        try (CloseableReadableData readableData = dataFactory.createReadableData(bytes, 10000, fileRepository)) {}
    }

    /**
     * Tests that the method DataFactory.createReadabeData(byte[],...) throws
     * an Exception on too large data (+1).
     * @throws Exception 
     */
    @Test(expected = FileUploadBase.SizeLimitExceededException.class)
    public void testDataFactoryCreateReadableData_byteArray_tooLarge1() throws Exception {
        DataFactory dataFactory = createDataFactory();
        byte[] bytes = new byte[10001];
        try (CloseableReadableData readableData = dataFactory.createReadableData(bytes, 10000, fileRepository)) {}
    }
    
    /**
     * Tests the method DataFactory.createReadabeData(boolean,...).
     * @throws Exception 
     */    
    @Test
    public void testDataFactoryCreateWritableData_boolean() throws Exception {
        DataFactory dataFactory = createDataFactory();
        
        byte[] bytes = "pqrstuvwxyz".getBytes(StandardCharsets.US_ASCII);
        int length = bytes.length;
        
        File file;
        
        // As FileOutputStream
        try (CloseableWritableData writeableData = dataFactory.createWritableData(false, fileRepository)) {
            // Write data to file
            try (OutputStream fos = writeableData.getAsFileOutputStream()) {
                fos.write(bytes);
            }
            
            ReadableData readableData = writeableData.toReadableData();
            
            // Check length
            assertEquals("length", length, readableData.getLength());
            
            // From file
            assertTrue("is file", readableData.isFile());
            
            // Can be read as byte array
            assertEquals("byte array", Hex.toHexString(bytes), Hex.toHexString(readableData.getAsByteArray()));
            
            // Can be read as stream
            assertEquals("stream", Hex.toHexString(bytes), Hex.toHexString(IOUtils.toByteArray(readableData.getAsInputStream())));
            
            // Can be read as file
            file = readableData.getAsFile();
            assertEquals("file", Hex.toHexString(bytes), Hex.toHexString(FileUtils.readFileToByteArray(file)));        
        }
        // File removed (auto-closeable)
        assertFalse("file removed", file.exists());
        
        // As in-memory outputstream
        try (CloseableWritableData writeableData = dataFactory.createWritableData(false, fileRepository)) {
            // Write data to file
            try (OutputStream fos = writeableData.getAsInMemoryOutputStream()) {
                fos.write(bytes);
            }
            
            ReadableData readableData = writeableData.toReadableData();
            
            // Check length
            assertEquals("length", length, readableData.getLength());
            
            // From file
            assertFalse("not file", readableData.isFile());
            
            // Can be read as byte array
            assertEquals("byte array", Hex.toHexString(bytes), Hex.toHexString(readableData.getAsByteArray()));
            
            // Can be read as stream
            assertEquals("stream", Hex.toHexString(bytes), Hex.toHexString(IOUtils.toByteArray(readableData.getAsInputStream())));
            
            // Can be read as file
            file = readableData.getAsFile();
            assertEquals("file", Hex.toHexString(bytes), Hex.toHexString(FileUtils.readFileToByteArray(file)));        
        }
        // File removed (auto-closeable)
        assertFalse("file removed", file.exists());
        
        // As any OutPutStream with defaultToDisk=false
        try (CloseableWritableData writeableData = dataFactory.createWritableData(false, fileRepository)) {
            // Write data to file
            try (OutputStream fos = writeableData.getAsOutputStream()) {
                fos.write(bytes);
            }
            
            ReadableData readableData = writeableData.toReadableData();
            
            // Check length
            assertEquals("length", length, readableData.getLength());
            
            // From file
            assertFalse("not file", readableData.isFile());
            
            // Can be read as byte array
            assertEquals("byte array", Hex.toHexString(bytes), Hex.toHexString(readableData.getAsByteArray()));
            
            // Can be read as stream
            assertEquals("stream", Hex.toHexString(bytes), Hex.toHexString(IOUtils.toByteArray(readableData.getAsInputStream())));
            
            // Can be read as file
            file = readableData.getAsFile();
            assertEquals("file", Hex.toHexString(bytes), Hex.toHexString(FileUtils.readFileToByteArray(file)));        
        }
        // File removed (auto-closeable)
        assertFalse("file removed", file.exists());
        
        // As any OutputStream with defaultToDisk=true
        try (CloseableWritableData writeableData = dataFactory.createWritableData(true, fileRepository)) {
            // Write data to file
            try (OutputStream fos = writeableData.getAsFileOutputStream()) {
                fos.write(bytes);
            }
            
            ReadableData readableData = writeableData.toReadableData();
            
            // Check length
            assertEquals("length", length, readableData.getLength());
            
            // From file
            assertTrue("is file", readableData.isFile());
            
            // Can be read as byte array
            assertEquals("byte array", Hex.toHexString(bytes), Hex.toHexString(readableData.getAsByteArray()));
            
            // Can be read as stream
            assertEquals("stream", Hex.toHexString(bytes), Hex.toHexString(IOUtils.toByteArray(readableData.getAsInputStream())));
            
            // Can be read as file
            file = readableData.getAsFile();
            assertEquals("file", Hex.toHexString(bytes), Hex.toHexString(FileUtils.readFileToByteArray(file)));        
        }
        // File removed (auto-closeable)
        assertFalse("file removed", file.exists());
        
        // As File
        try (CloseableWritableData writeableData = dataFactory.createWritableData(false, fileRepository)) {
            // Write data to file
            File outFile = writeableData.getAsFile();
            FileUtils.writeByteArrayToFile(outFile, bytes);
            
            ReadableData readableData = writeableData.toReadableData();
            
            // Check length
            assertEquals("length", length, readableData.getLength());
            
            // From file
            assertTrue("is file", readableData.isFile());
            
            // Can be read as byte array
            assertEquals("byte array", Hex.toHexString(bytes), Hex.toHexString(readableData.getAsByteArray()));
            
            // Can be read as stream
            assertEquals("stream", Hex.toHexString(bytes), Hex.toHexString(IOUtils.toByteArray(readableData.getAsInputStream())));
            
            // Can be read as file
            file = readableData.getAsFile();
            assertEquals("file", Hex.toHexString(bytes), Hex.toHexString(FileUtils.readFileToByteArray(file)));        
        }
        // File removed (auto-closeable)
        assertFalse("file removed", file.exists());
    }

    /**
     * Tests the method DataFactory.createReadabeData(FileItem,...).
     * @throws Exception 
     */
    @Test
    public void testDataFactoryCreateReadableData_fileItem() throws Exception {
        DataFactory dataFactory = createDataFactory();
        
        byte[] bytes = "ABCDEFGHIJKLM".getBytes(StandardCharsets.US_ASCII);
        int length = bytes.length;
        
        final DiskFileItemFactory factory = new DiskFileItemFactory();
        factory.setSizeThreshold(500);
        factory.setRepository(fileRepository);

        final BinaryFileUpload upload = new BinaryFileUpload(new ByteArrayInputStream(bytes), "application/octet-stream", factory);
        upload.setSizeMax(10000);

        File file;
        try (CloseableReadableData readableData = dataFactory.createReadableData(upload.parseTheRequest(), fileRepository)) {
            // Check length
            assertEquals("length", length, readableData.getLength());
            
            // Not from file
            assertFalse("not file", readableData.isFile());
            
            // Can be read as byte array
            assertEquals("byte array", Hex.toHexString(bytes), Hex.toHexString(readableData.getAsByteArray()));
            
            // Can be read as stream
            assertEquals("stream", Hex.toHexString(bytes), Hex.toHexString(IOUtils.toByteArray(readableData.getAsInputStream())));
            
            // Can be read as file
            file = readableData.getAsFile();
            assertEquals("file", Hex.toHexString(bytes), Hex.toHexString(FileUtils.readFileToByteArray(file)));
        }
        // File removed (auto-closeable)
        assertFalse("file removed", file.exists());
    }

    /**
     * Tests that the method DataFactory.createReadabeData(FileItem,...) throws
     * an Exception on too large data (+1).
     * @throws Exception 
     */    
    @Test(expected = FileUploadBase.SizeLimitExceededException.class)
    public void testDataFactoryCreateReadableData_fileItem_tooLarge1() throws Exception {
        DataFactory dataFactory = createDataFactory();
        
        byte[] bytes = new byte[1001];
        
        final DiskFileItemFactory factory = new DiskFileItemFactory();
        factory.setSizeThreshold(20);
        factory.setRepository(fileRepository);

        final BinaryFileUpload upload = new BinaryFileUpload(new ByteArrayInputStream(bytes), "application/octet-stream", factory);
        upload.setSizeMax(1000); // Will be too large

        try (CloseableReadableData readableData = dataFactory.createReadableData(upload.parseTheRequest(), fileRepository)) {}
    }

}
