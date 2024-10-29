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
package org.signserver.server.data.impl;

import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Output stream that doesn't automatically close file
 * when stream is closed.
 *
 * @author Selwyn Oh
 * @version $Id$
 */
public class NonClosingOutputStream extends OutputStream {
  private final FileChannel fileChannel;

  public NonClosingOutputStream(FileChannel fileChannel) {
      this.fileChannel = fileChannel;
  }

  @Override
  public void write(int b) throws IOException {
      byte[] singleByte = new byte[]{(byte) b};
      write(singleByte, 0, 1);
  }

  @Override
  public void write(byte[] b, int off, int len) throws IOException {
      ByteBuffer buffer = ByteBuffer.wrap(b, off, len);
      while (buffer.hasRemaining()) {
          fileChannel.write(buffer);
      }
  }

  @Override
  public void close() throws IOException {
      // Override close to do nothing, preventing the underlying FileChannel from being closed.
  }
}