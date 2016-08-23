/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.data.impl;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import org.apache.log4j.Logger;

/**
 *
 * @author user
 */
public class UploadUtil {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(UploadUtil.class);

    
    
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
