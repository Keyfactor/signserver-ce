/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.common.data;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

/**
 *
 * @author user
 */
public interface ReadableData {

    byte[] getAsByteArray() throws IOException;

    InputStream getAsInputStream() throws IOException;

    File getAsFile() throws IOException;
    
    long getLength();

    boolean isFile();
    
}
