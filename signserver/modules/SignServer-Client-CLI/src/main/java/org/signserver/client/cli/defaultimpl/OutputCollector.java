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

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

/**
 * Output collector encapsulating an OutputStream.
 * Can optionally handle the specific case of capturing output into a byte array
 * via a ByteArrayOutputStream.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class OutputCollector {
    private final OutputStream outputStream;
    private final boolean isByteArray;
    
    public OutputCollector(final OutputStream os, final boolean isByteArray) {
        outputStream = os;
        this.isByteArray = isByteArray;
    }
    
    public OutputCollector(final ByteArrayOutputStream bos) {
        outputStream = bos;
        isByteArray = true;
    }
    
    public OutputStream getOutputStream() {
        return outputStream;
    }
    
    public byte[] toByteArray() {
        if (!isByteArray) {
            throw new IllegalArgumentException("Collector is not based on a byte array");
        }
        
        return ((ByteArrayOutputStream) outputStream).toByteArray();
    }
}
