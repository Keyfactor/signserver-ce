/**
 * ***********************************************************************
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
 ************************************************************************
 */
package org.signserver.server.data.impl;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;

/**
 * Utility methods for request/response data handling.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class UploadUtil {
  
    // TODO: Move out of this class!
    public static byte[] digest(InputStream input, MessageDigest md) throws IOException {
        final byte[] buffer = new byte[4096]; 
        int n = 0;
        while (-1 != (n = input.read(buffer))) {
            md.update(buffer, 0, n);
        }
        return md.digest();
    }
    
}
