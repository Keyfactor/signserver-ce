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

package org.openxml4j.opc.internal.marshallers;

import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.openxml4j.exceptions.OpenXML4JException;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.StreamHelper;
import org.openxml4j.opc.internal.ZipHelper;

/**
 * Package core properties marshaller specialized for zipped package.
 * 
 * @author Julien Chable
 * @version 1.0
 */
public class ZipPackagePropertiesMarshaller extends PackagePropertiesMarshaller {

	@Override
	public boolean marshall(PackagePart part, OutputStream out)
			throws OpenXML4JException {
		if (!(out instanceof ZipOutputStream)) {
			throw new IllegalArgumentException("ZipOutputStream expected!");
		}
		ZipOutputStream zos = (ZipOutputStream) out;

		// Saving the part in the zip file
		ZipEntry ctEntry = new ZipEntry(ZipHelper
				.getZipItemNameFromOPCName(part.getPartName().getURI()
						.toString()));
		try {
			// Save in ZIP
			zos.putNextEntry(ctEntry); // Add entry in ZIP
			super.marshall(part, out); // Marshall the properties inside a XML
			// Document
			if (!StreamHelper.saveXmlInStream(xmlDoc, out)) {
				return false;
			}
			zos.closeEntry();
		} catch (IOException e) {
			throw new OpenXML4JException(e.getLocalizedMessage());
		}
		return true;
	}
}
