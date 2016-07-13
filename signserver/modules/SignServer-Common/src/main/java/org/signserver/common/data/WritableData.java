/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.common.data;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;

/**
 *
 * @author user
 */
public interface WritableData {

    File getAsFile() throws IOException;

    OutputStream getAsOutputStream() throws IOException;
    
    OutputStream getAsFileOutputStream() throws IOException;

    OutputStream getAsInMemoryOutputStream();
    
    ReadableData toReadableData();
    
}
