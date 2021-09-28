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
import java.io.IOException;
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
                                             final boolean clientSide, Map<String, String> extraOptions)
            throws IOException {
        if (clientSide) {
            throw new IllegalArgumentException("Client-side contruction is not supported");
        }
        return new StraightFileSpecificHandler((inFile), inFile.length());
    }

    @Override
    public FileSpecificHandler createHandler(final File inFile, final File outFile,
                                             final boolean clientSide,
                                             final Map<String, String> extraOptions,
                                             final String workerName)
            throws IOException {
        if (clientSide) {
            throw new IllegalArgumentException("Client-side contruction is not supported");
        }
        return new StraightFileSpecificHandler((inFile), inFile.length());
    }

    @Override
    public FileSpecificHandler createHandler(final File inFile, final File outFile,
                                             final boolean clientSide,
                                             final Map<String, String> extraOptions,
                                             final String workerName,
                                             final DocumentSignerFactory signerFactory,
                                             final Map<String, Object> requestContext,
                                             final Map<String, String> metadata)
            throws IOException {
        if (clientSide) {
            throw new IllegalArgumentException("Client-side contruction is not supported");
        }
        return new StraightFileSpecificHandler((inFile), inFile.length());
    }

    @Override
    public FileSpecificHandler createHandler(final File inFile, final File outFile,
                                             final boolean clientSide,
                                             final Map<String, String> extraOptions,
                                             final int workerId)
            throws IOException {
        if (clientSide) {
            throw new IllegalArgumentException("Client-side contruction is not supported");
        }
        return new StraightFileSpecificHandler((inFile), inFile.length());
    }

    @Override
    public FileSpecificHandler createHandler(final File inFile, final File outFile,
                                             final boolean clientSide,
                                             final Map<String, String> extraOptions,
                                             final int workerId,
                                             final DocumentSignerFactory signerFactory,
                                             final Map<String, Object> requestContext,
                                             final Map<String, String> metadata)
            throws IOException {
        if (clientSide) {
            throw new IllegalArgumentException("Client-side contruction is not supported");
        }
        return new StraightFileSpecificHandler((inFile), inFile.length());
    }

    @Override
    public FileSpecificHandler createHandler(final byte[] inData, final File outFile, final boolean clientSide, Map<String, String> extraOptions) {
        if (clientSide) {
            throw new IllegalArgumentException("Client-side contruction is not supported");
        }
        return new StraightFileSpecificHandler(inData);
    }

    @Override
    public FileSpecificHandler createHandler(final String fileType,
                                             final File inFile,
                                             final File outFile,
                                             final boolean clientSide, Map<String, String> extraOptions)
        throws IOException {
        if (clientSide) {
            throw new IllegalArgumentException("Client-side contruction is not supported");
        }
        return new StraightFileSpecificHandler(inFile,
                                               inFile.length());
    }

    @Override
    public FileSpecificHandler createHandler(final String fileType,
                                             final File inFile,
                                             final File outFile,
                                             final boolean clientSide,
                                             final Map<String, String> extraOptions,
                                             final String workerName)
        throws IOException {
        if (clientSide) {
            throw new IllegalArgumentException("Client-side contruction is not supported");
        }
        return new StraightFileSpecificHandler(inFile,
                                               inFile.length());
    }

    @Override
    public FileSpecificHandler createHandler(final String fileType,
                                             final File inFile,
                                             final File outFile,
                                             final boolean clientSide,
                                             final Map<String, String> extraOptions,
                                             final String workerName,
                                             final DocumentSignerFactory signerFactory,
                                             final Map<String, Object> requestContext,
                                             final Map<String, String> metadata)
        throws IOException {
        if (clientSide) {
            throw new IllegalArgumentException("Client-side contruction is not supported");
        }
        return new StraightFileSpecificHandler((inFile),
                                               inFile.length());
    }

    @Override
    public FileSpecificHandler createHandler(final String fileType,
                                             final File inFile,
                                             final File outFile,
                                             final boolean clientSide,
                                             final Map<String, String> extraOptions,
                                             final int workerId)
        throws IOException {
        if (clientSide) {
            throw new IllegalArgumentException("Client-side contruction is not supported");
        }
        return new StraightFileSpecificHandler((inFile),
                                               inFile.length());
    }

    @Override
    public FileSpecificHandler createHandler(final String fileType,
                                             final File inFile,
                                             final File outFile,
                                             final boolean clientSide,
                                             final Map<String, String> extraOptions,
                                             final int workerId,
                                             final DocumentSignerFactory signerFactory,
                                             final Map<String, Object> requestContext,
                                             final Map<String, String> metadata)
        throws IOException {
        if (clientSide) {
            throw new IllegalArgumentException("Client-side contruction is not supported");
        }
        return new StraightFileSpecificHandler((inFile),
                                               inFile.length());
    }

    @Override
    public FileSpecificHandler createHandler(final String fileType,
                                             final byte[] inData,
                                             final File outFile,
                                             final boolean clientSide, Map<String, String> extraOptions) {
        if (clientSide) {
            throw new IllegalArgumentException("Client-side contruction is not supported");
        }
        return new StraightFileSpecificHandler(inData);
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
