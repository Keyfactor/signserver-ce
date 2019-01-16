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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.dom4j.Document;
import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.StreamHelper;

/**
 * Zip implementation of the ContentTypeManager.
 * 
 * @author Julien Chable
 * @version 1.0
 * @see ContentTypeManager
 */
public class ZipContentTypeManager extends ContentTypeManager {

	/**
	 * Delegate constructor to the super constructor.
	 * 
	 * @param in
	 *            The input stream to parse to fill internal content type
	 *            collections.
	 * @throws InvalidFormatException
	 *             If the content types part content is not valid.
	 */
	public ZipContentTypeManager(InputStream in, Package pkg)
			throws InvalidFormatException {
		super(in, pkg);
	}

	@Override
	public boolean saveImpl(Document content, OutputStream out) {
		ZipOutputStream zos = null;
		if (out instanceof ZipOutputStream)
			zos = (ZipOutputStream) out;
		else
			zos = new ZipOutputStream(out);

		ZipEntry partEntry = new ZipEntry(CONTENT_TYPES_PART_NAME);
		try {
			// Referenced in ZIP
			zos.putNextEntry(partEntry);
			// Saving data in the ZIP file
			ByteArrayOutputStream outTemp = new ByteArrayOutputStream();
			StreamHelper.saveXmlInStream(content, out);
			InputStream ins = new ByteArrayInputStream(outTemp.toByteArray());
			byte[] buff = new byte[ZipHelper.READ_WRITE_FILE_BUFFER_SIZE];
			while (ins.available() > 0) {
				int resultRead = ins.read(buff);
				if (resultRead == -1) {
					// end of file reached
					break;
				} else {
					zos.write(buff, 0, resultRead);
				}
			}
			zos.closeEntry();
		} catch (IOException ioe) {
			logger.error("Cannot write: " + CONTENT_TYPES_PART_NAME
					+ " in Zip !", ioe);
			return false;
		}
		return true;
	}
}
