/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.data.impl;

import java.io.File;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadBase;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItem;
import org.apache.log4j.Logger;
import org.signserver.common.data.ReadableData;

/**
 *
 * @author user
 */
public class DefaultDataFactory implements DataFactory {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DefaultDataFactory.class);
    
    public DefaultDataFactory() {
        LOG.info("Loading default data factory");
    }

    @Override
    public CloseableReadableData createReadableData(byte[] data, long maxSize, File repository) throws FileUploadException {
        final long length = data.length;

        if (length > maxSize) {
            throw new FileUploadBase.SizeLimitExceededException(
                        String.format("the request was rejected because its size (%s) exceeds the configured maximum (%s)",
                                length, maxSize),
                               length, maxSize);
        }

        return new ByteArrayReadableData(data, repository);
    }

    @Override
    public CloseableReadableData createReadableData(FileItem item, File repository) {
        DiskFileItem dfi = (DiskFileItem) item;
        return new ByteArrayReadableData(dfi.get(), repository);
    }

    @Override
    public CloseableWritableData createWritableData(ReadableData readableData, File repository) {
        return new TemporarlyWritableData(readableData.isFile(), repository);
    }
    
    @Override
    public CloseableWritableData createWritableData(boolean defaultToDisk, File repository) {
        return new TemporarlyWritableData(defaultToDisk, repository);
    }

}
