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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import org.apache.commons.fileupload.FileUploadBase;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import static org.junit.Assert.*;
import org.signserver.server.data.impl.BinaryFileUpload;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.DataFactory;
import org.signserver.server.data.impl.DataUtils;
import org.signserver.server.data.impl.UploadConfig;

/**
 * Unit tests for LargeFileDataFactory.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class LargeFileDataFactoryUnitTest {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(LargeFileDataFactoryUnitTest.class);
    
    private final File fileRepository = new UploadConfig().getRepository();

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
     * Tests for the DataFactory.createReadableData(FileItem,...) method.
     * @throws Exception 
     */
    @Test
    public void testDataFactoryCreateReadableData_fileItem() throws Exception {
        DataFactory dataFactory = new LargeFileDataFactory();
        
        byte[] bytes = "ABCDEFGHIJKLM".getBytes(StandardCharsets.US_ASCII);
        int length = bytes.length;
        
        final DiskFileItemFactory factory = new DiskFileItemFactory();
        factory.setSizeThreshold(500);
        factory.setRepository(fileRepository);

        BinaryFileUpload upload = new BinaryFileUpload(new ByteArrayInputStream(bytes), "application/octet-stream", factory);
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
     * Tests that the DataFactory.createReadableData(FileItem,...) method
     * throws an Exception when the file is too large.
     * @throws Exception 
     */
    @Test(expected = FileUploadBase.SizeLimitExceededException.class)
    public void testDataFactoryCreateReadableData_fileItem_tooLarge1() throws Exception {
        DataFactory dataFactory = new LargeFileDataFactory();
        
        byte[] bytes = new byte[1001];
        
        final DiskFileItemFactory factory = new DiskFileItemFactory();
        factory.setSizeThreshold(20);
        factory.setRepository(fileRepository);

        final BinaryFileUpload upload = new BinaryFileUpload(new ByteArrayInputStream(bytes), "application/octet-stream", factory);
        upload.setSizeMax(1000); // Will be too large

        try (CloseableReadableData readableData = dataFactory.createReadableData(upload.parseTheRequest(), fileRepository)) {}
    }

}
