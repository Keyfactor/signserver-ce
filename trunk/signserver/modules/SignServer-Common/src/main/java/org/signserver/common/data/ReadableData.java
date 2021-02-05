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
package org.signserver.common.data;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

/**
 * Abstraction for request data that can be read using various different methods.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface ReadableData {

    /**
     * Get the data as an in-memory byte array.
     * If the data was backed by a file it will first be read into memory.
     * @return the byte array
     * @throws IOException in case of error reading the data
     */
    byte[] getAsByteArray() throws IOException;

    /**
     * Get the data as an InputStream.
     * @return the input stream
     * @throws IOException  in case of error reading the data
     */
    InputStream getAsInputStream() throws IOException;

    /**
     * Get the data as a file.
     * If the data was not already in a file it will be written out first.
     * @return the file
     * @throws IOException  in case of error writing the data
     */
    File getAsFile() throws IOException;
    
    /**
     * @return the size of the data in memory or on disk
     */
    long getLength();

    /**
     * @return true if the backing data was in a file
     */
    boolean isFile();
    
}
