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

/**
 * Input source encapsulting information about an input stream with an associated
 * size and optionally a file name.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class InputSource {
    private final InputStream inputStream;
    private final int size;
    private final String fileName;
    
    public InputSource(final InputStream inputStream, final int size,
                       final String fileName) {
        this.inputStream = inputStream;
        this.size = size;
        this.fileName = fileName;
    }
    
    public InputSource(final InputStream inputStream, final int size) {
        this(inputStream, size, null);
    }
    
    public InputStream getInputStream() {
        return inputStream;
    }
    
    public int getSize() {
        return size;
    }
    
    public String getFileName() {
        return fileName;
    }
}