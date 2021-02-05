/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.server.cesecore.util;

import java.io.IOException;

/**
 * Thrown when there's too much data, e.g. in a stream when using FileTools.streamCopyWithLimit
 * 
 * @version $Id: StreamSizeLimitExceededException.java 34821 2020-04-07 09:01:36Z bastianf $
 */
public class StreamSizeLimitExceededException extends IOException {

    private static final long serialVersionUID = 1L;

    public StreamSizeLimitExceededException() {
        super();
    }
    
    public StreamSizeLimitExceededException(String message) {
        super(message);
    }

    public StreamSizeLimitExceededException(String message, Throwable cause) {
        super(message, cause);
    }

    public StreamSizeLimitExceededException(Throwable cause) {
        super(cause);
    }
    
}
