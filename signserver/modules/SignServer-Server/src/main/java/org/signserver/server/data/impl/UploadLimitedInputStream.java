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
import org.apache.commons.fileupload.FileUploadBase;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.util.LimitedInputStream;

/**
 * InputStream wrapper throwing exception if too many bytes are read.
 *
 * Emulates what commons file upload already does.
 *
 * @see LimitedInputStream
 * @see SizeLimitExceededException
 */
public class UploadLimitedInputStream extends LimitedInputStream {

    public UploadLimitedInputStream(InputStream inputStream, long pSizeMax) {
        super(inputStream, pSizeMax);
    }

    @Override
    protected void raiseError(long pSizeMax, long pCount) throws IOException {
        FileUploadException ex = new FileUploadBase.SizeLimitExceededException(
                format("the request was rejected because its size (%s) exceeds the configured maximum (%s)", 
                        pCount, Long.valueOf(pSizeMax)), 
                        pCount, pSizeMax);
        throw new FileUploadBase.FileUploadIOException(ex);
    }
    
}
