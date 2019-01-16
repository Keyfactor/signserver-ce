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
import java.util.Map;
import org.signserver.client.cli.defaultimpl.FileSpecificHandler;

/**
 * Interface for factory classes capable of creating FileSpecificHandlerS.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public interface FileSpecificHandlerFactory {
    /**
     * Create a handler for given input and output file.
     * 
     * @param inFile input for the handler given as a file
     * @param outFile output file for the handler to use
     * @param clientSide true if the handler should be able to do client-side hashing and construction
     * @param extraOptions extra settings for the implementation
     * @return A FileSpecificHandler
     * @throws java.io.IOException if unable to use the input file, i.e. file non-existing
     */
    FileSpecificHandler createHandler(File inFile, File outFile, boolean clientSide, Map<String, String> extraOptions)
            throws IOException;
    
    /**
     * Create a handler given an input stream and an output file.
     * 
     * @param inStream input for the handler given as an input stream
     * @param size the number of bytes provided in the input stream
     * @param outFile output file for the handler to use
     * @param clientSide true if the handler should be able to do client-side hashing and construction
     * @param extraOptions extra settings for the implementation
     * @return A FileSpecificHandler 
     */
    FileSpecificHandler createHandler(InputStream inStream, long size, File outFile, boolean clientSide, Map<String, String> extraOptions);
    
    /**
     * Create a file specific handler given a file type name, input, and output
     * files.
     * 
     * @param fileType file type identifier, overriding any autodetection done by the factory
     * @param inFile input for the handler given as a file
     * @param outFile output file for the handler to use
     * @param clientSide true if the handler should be able to do client-side hashing and construction
     * @param extraOptions extra settings for the implementation
     * @return A FileSpecificHandler
     * @throws IOException if unable to use the input file, i.e. file non-existing
     */
    FileSpecificHandler createHandler(String fileType, File inFile, File outFile,
                                      boolean clientSide, Map<String, String> extraOptions)
            throws IOException;
    
    /**
     * Create a file specific handler given a file type name, input stream and
     * an output file.
     * 
     * @param fileType file type identifier, overriding any autodetection done by the factory
     * @param inStream input for the handler given as an input stream
     * @param size the number of bytes provided in the input stream
     * @param outFile output file for the handler to use
     * @param clientSide true if the handler should be able to do client-side hashing and construction
     * @param extraOptions extra settings for the implementation
     * @return A FileSpecificHandler 
     */
    FileSpecificHandler createHandler(String fileType, InputStream inStream,
                                      long size,
                                      File outFile, boolean clientSide, Map<String, String> extraOptions);
    
    /**
     * Return true if the factory can create a client-side hashing and
     * contruction-capable handler.
     * 
     * @return True if can create client-side capable handler
     */
    boolean canCreateClientSideCapableHandler();
    
    /**
     * Return true if the factory can create a handler for a given file type ID.
     * 
     * @param fileType
     * @return True if fileType can be handled
     */
    boolean canHandleFileType(String fileType);
}
