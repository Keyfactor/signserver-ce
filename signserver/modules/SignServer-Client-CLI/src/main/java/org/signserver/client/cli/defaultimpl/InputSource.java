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
package org.signserver.client.cli.defaultimpl;

import java.io.InputStream;
import java.util.Map;

/**
 * Input source encapsulting information about an input stream with an associated
 * size and optionally a file name.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class InputSource {
    private final InputStream inputStream;
    private final long size;
    private final String fileName;
    private final Map<String, String> metadata;

    public InputSource(final InputStream inputStream, final long size,
                       final String fileName,
                       final Map<String, String> metadata) {
        this.inputStream = inputStream;
        this.size = size;
        this.fileName = fileName;
        this.metadata = metadata;
    }

    public InputSource(final InputStream inputStream, final long size,
                       final Map<String, String> metadata) {
        this(inputStream, size, null, metadata);
    }

    public InputSource(final InputStream inputStream, final long size,
                       final String fileName) {
        this(inputStream, size, fileName, null);
    }
    
    public InputSource(final InputStream inputStream, final long size) {
        this(inputStream, size, null, null);
    }
    
    public InputStream getInputStream() {
        return inputStream;
    }
    
    public long getSize() {
        return size;
    }
    
    public String getFileName() {
        return fileName;
    }

    public Map<String, String> getMetadata() {
        return metadata;
    }
}