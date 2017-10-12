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
package org.signserver.client.cli.spi;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import org.signserver.client.cli.defaultimpl.FileSpecificHandler;

/**
 * Interface for factory classes capbable of creating FileSpecificHandlerS.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public interface FileSpecificHandlerFactory {
    /**
     * Create a handler for given input and output file.
     * 
     * @param inFile
     * @param outFile
     * @return A FileSpecificHandler
     * @throws java.io.IOException
     */
    FileSpecificHandler createHandler(File inFile, File outFile, boolean clientSide)
            throws IOException;
    
    /**
     * Create a handler given an input stream and an output file.
     * 
     * @param inStream
     * @param outFile
     * @return 
     * @throws java.io.IOException 
     */
    FileSpecificHandler createHandler(InputStream inStream, File outFile, boolean clientSide)
            throws IOException;
    
    /**
     * Create a file specific handler given a file type name, input, and output
     * files.
     * 
     * @param fileType
     * @param inFile
     * @param outFile
     * @param clientSide
     * @return
     * @throws IOException 
     */
    FileSpecificHandler createHandler(String fileType, File inFile, File outFile,
                                      boolean clientSide)
            throws IOException;
    
    /**
     * Create a file specific handler given a file type name, input stream and
     * an output file.
     * 
     * @param fileType
     * @param inStream
     * @param outFile
     * @param clientSide
     * @return
     * @throws IOException 
     */
    FileSpecificHandler createHandler(String fileType, InputStream inStream,
                                      File outFile, boolean clientSide) throws IOException;
}
