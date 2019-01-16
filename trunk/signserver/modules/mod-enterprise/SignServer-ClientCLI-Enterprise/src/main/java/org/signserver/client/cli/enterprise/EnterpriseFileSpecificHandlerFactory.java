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
package org.signserver.client.cli.enterprise;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;
import java.util.Map;
import org.apache.log4j.Logger;
import org.signserver.client.cli.defaultimpl.FileSpecificHandler;
import org.signserver.client.cli.defaultimpl.StraightFileSpecificHandler;
import org.signserver.client.cli.spi.FileSpecificHandlerFactory;
import org.signserver.module.jarchive.signer.JArchiveOptions;
import org.signserver.module.jarchive.signer.JArchiveSigner;

/**
 * Version of the FileSpecificHandlerFactory that can create FileSpecificHandlerS
 * capable of performing client-side hashing and contruction of certain formats.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class EnterpriseFileSpecificHandlerFactory implements FileSpecificHandlerFactory {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(EnterpriseFileSpecificHandlerFactory.class);

    private static enum FileType {
        /** Portable executable */
        PE,
        
        /** Windows installer */
        MSI,
        
        /** ZIP file (could be a JAR). */
        ZIP,
    }

    
    @Override
    public FileSpecificHandler createHandler(final File inFile, final File outFile,
                                             final boolean clientSide, Map<String, String> extraOptions) throws IOException {
        if (clientSide) {
            final FileType type = getTypeOfFile(new BufferedInputStream(new FileInputStream(inFile)));
        
            return createHandler(type, inFile, outFile, extraOptions);
        } else {
            return new StraightFileSpecificHandler(new FileInputStream(inFile),
                                                   inFile.length());
        }
    }
    
    @Override
    public FileSpecificHandler createHandler(final String fileType,
                                             final File inFile, final File outFile,
                                             final boolean clientSide, Map<String, String> extraOptions)
            throws IOException {
        if (clientSide) {
            final FileType type = FileType.valueOf(fileType.toUpperCase(Locale.ENGLISH));

            return createHandler(type, inFile, outFile, extraOptions);
        } else {
            return new StraightFileSpecificHandler(new FileInputStream(inFile),
                                                   inFile.length());
        }
    }

    @Override
    public FileSpecificHandler createHandler(final InputStream inStream,
                                             final long size,
                                             final File outFile,
                                             final boolean clientSide, Map<String, String> extraOptions) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    @Override
    public FileSpecificHandler createHandler(final String fileType,
                                             final InputStream inStream,
                                             final long size,
                                             final File outFile,
                                             final boolean clientSide, Map<String, String> extraOptions) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    @Override
    public boolean canCreateClientSideCapableHandler() {
        return true;
    }
    
    @Override
    public boolean canHandleFileType(String fileType) {
        try {
            final FileType type = FileType.valueOf(fileType.toUpperCase());
            
            return true;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private FileSpecificHandler createHandler(final FileType type,
                                              final File inFile, final File outFile, final Map<String, String> extraOptions) {
        switch (type) {
            case PE:
                return new PEFileSpecificHandler(inFile, outFile);
            case MSI:
                return new MSIFileSpecificHandler(inFile, outFile);
            case ZIP:
                // Only supported name type as KEYALIAS not available on client-side
                extraOptions.put("SIGNATURE_NAME_TYPE", JArchiveSigner.SignatureNameType.VALUE.name());
                String signatureNameValue = extraOptions.get("SIGNATURE_NAME_VALUE");
                if (signatureNameValue == null || signatureNameValue.trim().isEmpty()) {
                    extraOptions.put("SIGNATURE_NAME_VALUE", "SIGNSERV");
                }
                
                // Parse the options
                JArchiveOptions options = new JArchiveOptions(extraOptions);
                if (!options.getConfigErrors().isEmpty()) {
                    throw new IllegalArgumentException("Incorrect JAR signer options: " + options.getConfigErrors());
                }
                long timestamp = System.currentTimeMillis();

                return new JarFileSpecificHandler(inFile, outFile, options.isZipAlign() ? 4 : 0, options.isKeepSignatures(), options.isReplaceSignature(), options.getSignatureNameValue(), timestamp);
            default:
                throw new IllegalArgumentException("Unknown file type");
        }
    }
    
    /**
     * Determine the file type based on "magic bytes".
     * Copied from MSAuthCodeSigner: TODO: might refactor this out (along with the
     * file type enum).
     * 
     * @param input stream
     * @return file type (PE or MSI)
     */
    private FileType getTypeOfFile(final InputStream in)
        throws FileNotFoundException, IOException {
        
        final byte[] magic = new byte[8];
        final FileType type;
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Input stream: " + in.getClass().getName());
        }
        
        in.mark(8);
        
        int bytesRead = in.read(magic, 0, 8);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Bytes read: " + bytesRead);
        }
        
        if (bytesRead >= 2 && magic[0] == 'M' && magic[1] == 'Z') {
            type = FileType.PE;
        } else if (bytesRead >= 8 &&
                   magic[0] == (byte) 0xD0 && magic[1] == (byte) 0xCF &&
                   magic[2] == (byte) 0x11 && magic[3] == (byte) 0xE0 &&
                   magic[4] == (byte) 0xA1 && magic[5] == (byte) 0xB1 &&
                   magic[6] == (byte) 0x1A && magic[7] == (byte) 0xE1) {
            type = FileType.MSI;
        } else if (bytesRead >= 2 && magic[0] == 'P' && magic[1] == 'K') {
            type = FileType.ZIP;
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unsupported file type");
                if (bytesRead > 0) {
                    final StringBuilder sb = new StringBuilder();
                    
                    sb.append("Content: ");
                    for (int i = 0; i < bytesRead; i++) {
                        sb.append(String.format("%02X ", magic[i]));
                    }
                    LOG.debug(sb.toString());
                }
            }
            
            throw new IllegalArgumentException("Unsupported file type");
        }
        
        in.reset();
        return type;
    }
}
