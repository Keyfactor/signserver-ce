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
package org.signserver.testutils;

import java.io.IOException;
import java.io.OutputStream;

/**
 * OutputStream outputting to multiple streams.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TeeOutputStream extends OutputStream {

    private OutputStream[] streams;

    /**
     * Constructs an instance of TeeOuputStream which outputs to all supplied
     * streams.
     * @param streams A number of streams to output to
     */
    public TeeOutputStream(OutputStream... streams) {
        this.streams = streams;
    }
    
    @Override
    public void write(int b) throws IOException {
        for (OutputStream out : streams) {
            out.write(b);
        }
    }
    
}
