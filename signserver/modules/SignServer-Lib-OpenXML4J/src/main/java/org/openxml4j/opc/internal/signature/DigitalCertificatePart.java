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

package org.openxml4j.opc.internal.signature;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;

import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.exceptions.OpenXML4JException;
import org.openxml4j.exceptions.OpenXML4JRuntimeException;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackagePartName;
import org.openxml4j.opc.internal.ContentType;

/**
 * Digital certificate part.
 * 
 * @author Julien Chable
 * @version 0.1
 */
public final class DigitalCertificatePart extends PackagePart {

	private X509Certificate certificate;

	private final static ContentType contentType;

	private final static String relationshipType = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/certificate";

	private final static String extension = ".cer";
	
	static {
		try {
			contentType = new ContentType(
					"application/vnd.openxmlformats-package.digital-signature-certificate");
		} catch (InvalidFormatException e) {
			throw new OpenXML4JRuntimeException(
					"Can't create the digital certificate part content type ! This exception should never be raise, please contact the project development team.");
		}
	}
	
	DigitalCertificatePart(Package parentPackage, PackagePartName partName) throws InvalidFormatException{
		super(parentPackage, partName, contentType);
	}
	
	X509Certificate getCertificate()
	{
		if (this.certificate == null)
		{
			
		}
		
		return this.certificate;
	}

	@Override
	public void close() {
		// TODO Auto-generated method stub

	}

	@Override
	public void flush() {
		// TODO Auto-generated method stub

	}

	@Override
	protected InputStream getInputStreamImpl() throws IOException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected OutputStream getOutputStreamImpl() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean load(InputStream ios) throws InvalidFormatException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean save(OutputStream zos) throws OpenXML4JException {
		// TODO Auto-generated method stub
		return false;
	}

	// TODO Introduire le concept de partie typée dés cette partie
}
