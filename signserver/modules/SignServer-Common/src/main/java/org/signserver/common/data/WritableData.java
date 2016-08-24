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
import java.io.OutputStream;

/**
 * Abstraction for response data that can be written using various different
 * methods.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface WritableData {

    File getAsFile() throws IOException;

    OutputStream getAsOutputStream() throws IOException;
    
    OutputStream getAsFileOutputStream() throws IOException;

    OutputStream getAsInMemoryOutputStream();
    
    ReadableData toReadableData();
    
}
