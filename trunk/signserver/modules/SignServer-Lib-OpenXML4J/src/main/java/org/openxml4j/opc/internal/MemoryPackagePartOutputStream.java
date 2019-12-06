/* ====================================================================
   Licensed to the Apache Software Foundation (ASF) under one or more
   contributor license agreements.  See the NOTICE file distributed with
   this work for additional information regarding copyright ownership.
   The ASF licenses this file to You under the Apache License, Version 2.0
   (the "License"); you may not use this file except in compliance with
   the License.  You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
==================================================================== 

 * Copyright (c) 2006, Wygwam
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met: 
 * 
 * - Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation and/or 
 * other materials provided with the distribution.
 * - Neither the name of Wygwam nor the names of its contributors may be 
 * used to endorse or promote products derived from this software without 
 * specific prior written permission. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT 
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.openxml4j.opc.internal;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Build an output stream for MemoryPackagePart.
 * 
 * @author Julien Chable
 * @version 1.0
 */
public final class MemoryPackagePartOutputStream extends OutputStream {

	private MemoryPackagePart part;

	private ByteArrayOutputStream buff;

	public MemoryPackagePartOutputStream(MemoryPackagePart part) {
		this.part = part;
		buff = new ByteArrayOutputStream();
	}

	@Override
	public void write(int b) throws IOException {
		buff.write(b);
	}

	/**
	 * Close this stream and flush the content.
	 * @see #flush() 
	 */
	@Override
	public void close() throws IOException {
		this.flush();
	}

	/**
	 * Flush this output stream. This method is called by the close() method.
	 * Warning : don't call this method for output consistency.
	 * @see #close()
	 */
	@Override
	public void flush() throws IOException {
		buff.flush();
		if (part.data != null) {
			byte[] newArray = new byte[part.data.length + buff.size()];
			// copy the previous contents of part.data in newArray
			System.arraycopy(part.data, 0, newArray, 0, part.data.length);

			// append the newly added data
			byte[] buffArr = buff.toByteArray();
			System.arraycopy(buffArr, 0, newArray, part.data.length,
					buffArr.length);

			// save the result as new data
			part.data = newArray;
		} else {
			// was empty, just fill it
			part.data = buff.toByteArray();
		}
		
		/* 
		 * Clear this streams buffer, in case flush() is called a second time
		 * Fix bug 1921637 - provided by Rainer Schwarze
		 */
		buff.reset();
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		buff.write(b, off, len);
	}

	@Override
	public void write(byte[] b) throws IOException {
		buff.write(b);
	}
}
