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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import org.signserver.client.cli.spi.FileSpecificHandlerFactory;

/**
 * Basic implementation of FileSpecificHandlerFactory that just creates a
 * straight no-op handler.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class DefaultFileSpecificHandlerFactory implements FileSpecificHandlerFactory {

    @Override
    public FileSpecificHandler createHandler(final File inFile, final File outFile,
                                             final boolean clientSide, Map<String, String> metadata)
            throws IOException {
        if (clientSide) {
            throw new IllegalArgumentException("Client-side contruction is not supported");
        }
        return new StraightFileSpecificHandler(new FileInputStream(inFile), inFile.length());
    }

    @Override
    public FileSpecificHandler createHandler(final InputStream inStream,
                                             final long size,
                                             final File outFile,
                                             final boolean clientSide, Map<String, String> metadata) {
        if (clientSide) {
            throw new IllegalArgumentException("Client-side contruction is not supported");
        }
        return new StraightFileSpecificHandler(inStream, size);
    }

    @Override
    public FileSpecificHandler createHandler(final String fileType,
                                             final File inFile,
                                             final File outFile,
                                             final boolean clientSide, Map<String, String> metadata)
        throws IOException {
        if (clientSide) {
            throw new IllegalArgumentException("Client-side contruction is not supported");
        }
        return new StraightFileSpecificHandler(new FileInputStream(inFile),
                                               inFile.length());
    }

    @Override
    public FileSpecificHandler createHandler(final String fileType,
                                             final InputStream inStream,
                                             final long size,
                                             final File outFile,
                                             final boolean clientSide, Map<String, String> metadata) {
        if (clientSide) {
            throw new IllegalArgumentException("Client-side contruction is not supported");
        }
        return new StraightFileSpecificHandler(inStream, size);
    }

    @Override
    public boolean canCreateClientSideCapableHandler() {
        return false;
    }

    @Override
    public boolean canHandleFileType(String fileType) {
        throw new UnsupportedOperationException("Not supported yet.");
    }  
}
