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

import jakarta.ws.rs.core.EntityPart;
import java.io.IOException;
import java.io.InputStream;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadBase;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItem;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.signserver.common.data.ReadableData;

/**
 * Implementation of the DataFactory.
 *
 * @author Markus Kilås
 * @version $Id$
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
    public CloseableReadableData createReadableData(EntityPart item, long maxSize, File repository) throws FileUploadBase.FileUploadIOException, IOException {
        try (InputStream in = new UploadLimitedInputStream(item.getContent(), maxSize)) {
            return new ByteArrayReadableData(IOUtils.toByteArray(in), repository);
        }
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
