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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import org.signserver.common.IllegalRequestException;

/**
 * Interface for handling signing of specific file types.
 *
 * @author Marcus Lundblad
 * @author Markus Kilås
 * @version $Id$
 */
public interface FileSpecificHandler extends AutoCloseable {

    /**
     * @return True if the implementation returns a hash as signature input data or False for other data.
     */
    boolean isSignatureInputHash();
    
    /**
     * Phase 1: compute the signature input from the input file to send to SignServer
     * for creating the signature.
     * 
     * The signature input could be a hash or a file with hashes depending on the
     * implementation.
     *
     * @param algorithm Digest algorithm to use
     * @return the signature input
     * @throws NoSuchAlgorithmException
     * @throws IOException typically in case of issues reading the input file or writing to the output file
     * @throws IllegalRequestException for example: if file is already signed
     */
    InputSource produceSignatureInput(String algorithm) throws NoSuchAlgorithmException, IOException, IllegalRequestException;
    
    /**
     * Phase 2: Finalize the output file by embedding the provided signature.
     *
     * @param oc Output collector to obtain output to embed in the output file
     * @throws IOException typically in case of issues writing to the output file
     * @throws IllegalArgumentException typically in case the output collector is unfit for assembling the result
     */
    void assemble(OutputCollector oc) throws IOException, IllegalArgumentException;

    /**
     * Closes any input and output files and/or streams. 
     */
    @Override
    void close();
    
    /**
     * Get a file type identifier for the handler to use as metadata for the
     * signers (applicable for client-side hashing and construction-aware
     * handlers).
     * 
     * @return The type identifier, or null if not applicable
     */
    String getFileTypeIdentifier();

}
