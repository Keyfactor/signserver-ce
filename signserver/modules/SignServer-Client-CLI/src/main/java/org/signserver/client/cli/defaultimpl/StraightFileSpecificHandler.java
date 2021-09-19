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
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import org.apache.log4j.Logger;

/**
 * Version of the FileSpecificHandler for passing input directly to a signer
 * for server-side signing and pass the result through to the resulting file.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class StraightFileSpecificHandler implements FileSpecificHandler {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(StraightFileSpecificHandler.class);
    
    private final InputStream inputStream;
    private final File file;
    private final long size;
    
    private Collection<InputSource> sourcesToClose = new ArrayList<InputSource>();
    
    public StraightFileSpecificHandler(final File file,
                                       final long size) {
        this.file = file;
        this.inputStream = null;
        this.size = size;
    }

    public StraightFileSpecificHandler(final InputStream inputStream,
                                       final long size) {
        this.file = null;
        this.inputStream = inputStream;
        this.size = size;
    }
    
    @Override
    public boolean isSignatureInputHash() {
        return false;
    }

    @Override
    public InputSource produceSignatureInput(String algorithm) throws NoSuchAlgorithmException, IOException {
        if (file != null) {
            return closeLater(new InputSource(file, size));
        } else {
            return new InputSource(inputStream, size);
        }
    }

    @Override
    public void assemble(OutputCollector oc) throws IOException, IllegalArgumentException {
        oc.getOutputStream().close();
    }

    private InputSource closeLater(InputSource source) {
        sourcesToClose.add(source);
        return source;
    }
    
    @Override
    public void close() {
        if (inputStream != null) {
            try {
                inputStream.close();
            } catch (IOException ex) {
                LOG.warn("Unable to close resource: " + ex.getLocalizedMessage());
            }
        }
        for (InputSource source : sourcesToClose) {
            try {
                source.close();
            } catch (IOException ex) {
                LOG.warn("Unable to close resource: " + ex.getLocalizedMessage());
            }
        }
    }

    @Override
    public String getFileTypeIdentifier() {
        return null;
    }
    
    @Override
    public InputSource producePreRequestInput() {
        // return null for default implementation
           return null;
    }

    @Override
    public void assemblePreResponse(OutputCollector oc) {
       // Do nothing in default implementation
    }
}
