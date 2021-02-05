/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.odftoolkit.odfdom.pkg;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * This class reads from an InputStream and writes to an OutputStream.
 * No streams will be closed - calling classes must do this.
 */
class StreamHelper {

    // 4096 is thought to be the minimum page size for most systems;
    // change this for optimization
    public static final int PAGE_SIZE = 4096;
    private InputStream in;
    private OutputStream out;
    private boolean mStreamed;

    /**
     * Read from the input stream and write to the output. This method
     * does not close any stream; calling methods must take care of that.
     * @throws IOException when io error happens
     */
    static void stream(InputStream in, OutputStream out) throws IOException {
        StreamHelper s = new StreamHelper(in, out);
        s.stream();
    }

    /**
     * Create a new StreamHelper
     * @param in the input stream used for reading
     * @param out the output stream written to
     */
    StreamHelper(InputStream in, OutputStream out) {
        this.in = in;
        this.out = out;
        mStreamed = false;
    }

    /**
     * Read from the input stream and write to the output. This method can only
     * be called once. A second call will result in an IOException. This method
     * does not close any stream; calling methods must take care of that.
     * @throws IOException when io error happens
     */
    void stream() throws IOException {
        if (mStreamed) throw new IOException();
        byte[] buf = new byte[PAGE_SIZE];
        int r = 0;
        // let npe happen if one of the streams is null
        while ((r = in.read(buf, 0, PAGE_SIZE)) > -1) {
            out.write(buf, 0, r);
        }
        // free the references
        in = null;
        out = null;
        mStreamed = true;
    }
}
