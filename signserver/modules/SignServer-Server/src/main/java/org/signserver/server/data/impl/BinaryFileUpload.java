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

import java.io.IOException;
import java.io.InputStream;
import static java.lang.String.format;
import java.util.Collections;
import java.util.List;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileItemFactory;
import org.apache.commons.fileupload.FileUpload;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.RequestContext;
import org.apache.commons.fileupload.util.LimitedInputStream;
import org.apache.commons.fileupload.util.Streams;

/**
 * File upload for one single binary file (i.e. not mixed/multipart).
 *
 * Use parseTheRequest() to get a FileItem.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class BinaryFileUpload extends FileUpload {
    
    private final InputStream input;
    private final String contentType;

    /**
     * Create a FileUpload from the provided InputStream.
     *
     * @param input to read the data from
     * @param contentType of the data
     * @param fileItemFactory to use for creating the FileItem
     */
    public BinaryFileUpload(InputStream input, String contentType, FileItemFactory fileItemFactory) {
        super(fileItemFactory);
        this.contentType = contentType;
        this.input = input;
    }

    @Override
    public List<FileItem> parseRequest(RequestContext ctx) throws FileUploadException {
        return Collections.singletonList(parseTheRequest());
    }
    
    /**
     * Read the InputStream as a FileItem.
     * @return the parsed FileItem
     * @throws FileUploadException in case of error or to large input etc. 
     */
    public FileItem parseTheRequest() throws FileUploadException {
        FileItem fileItem = null;
        boolean successful = false;
        try {
            FileItemFactory fac = getFileItemFactory();
            if (fac == null) {
                throw new NullPointerException("No FileItemFactory has been set.");
            }
            fileItem = fac.createItem("data", contentType, false, null);
            Streams.copy(new LimitedInputStream(input, getSizeMax()) {
                @Override
                protected void raiseError(long pSizeMax, long pCount) throws IOException {
                    FileUploadException ex = new SizeLimitExceededException(
                        format("the request was rejected because its size (%s) exceeds the configured maximum (%s)",
                            pCount, pSizeMax),
                           pCount, pSizeMax);
                    throw new FileUploadIOException(ex);
                }
            }, fileItem.getOutputStream(), true);
            successful = true;
            return fileItem;
        } catch (FileUploadIOException e) {
            throw (FileUploadException) e.getCause();
        } catch (IOException e) {
            throw new FileUploadException(e.getMessage(), e);
        } finally {
            if (!successful) {
                if (fileItem != null) {
                    try {
                        fileItem.delete();
                    } catch (Throwable ignored) {} // NOPMD ignore it
                }
            }
        }
    }
    
}
