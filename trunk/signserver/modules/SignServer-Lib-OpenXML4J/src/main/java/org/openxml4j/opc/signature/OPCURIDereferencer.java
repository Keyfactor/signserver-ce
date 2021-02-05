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

package org.openxml4j.opc.signature;

import java.io.InputStream;

import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;

import org.dom4j.Document;
import org.dom4j.io.DOMWriter;
import org.dom4j.io.SAXReader;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackagingURIHelper;

/**
 * 
 * implementation of URIDereferencer for OPC
 * 
 * @author aziz.goktepe (aka rayback_2)
 * 
 * patch originally created for SignServer project {@link http://www.signserver.org}
 * 
 */
public class OPCURIDereferencer implements URIDereferencer {

	Package p;
	URIDereferencer defaultURIDereferencer;

	public OPCURIDereferencer(Package pPackage,
			URIDereferencer pDefaultURIDereferencer) {
		p = pPackage;
		defaultURIDereferencer = pDefaultURIDereferencer;
	}

	@Override
	public Data dereference(URIReference arg0, XMLCryptoContext arg1)
			throws URIReferenceException {

		// if the URI to be dereferenced does not start with '/' character then
		// it is not the package part [M1.4]
		if (!arg0.getURI().startsWith("/")) {
			return defaultURIDereferencer.dereference(arg0, arg1);
		}

		// remove ?ContenType=type_def from URI
		String partName = arg0.getURI().toString().split("\\?")[0];

		// open part for reading
		SAXReader docReader = new SAXReader();
		PackagePart part;
		try {

			part = p.getPart(PackagingURIHelper.createPartName(partName));
			InputStream is = part.getInputStream();

			if (part.isRelationshipPart()) {
				// if it is relationship part we are dereferencing then it
				// should be dereferenced as nodeset
				Document doc4jRet = docReader.read(is);

				// construct return data from doc4j document
				org.dom4j.io.DOMWriter dw = new DOMWriter();
				final org.w3c.dom.Document docRes = dw.write(doc4jRet);

				OX4JNodeSetData opcNodeSet = new OX4JNodeSetData(docRes);
				return opcNodeSet;

			} else {
				// if it is package part we are dereferencing then it should be
				// dereferenced as octetstream
				return new OctetStreamData(is);

			}

		} catch (Exception e) {
			throw new URIReferenceException(e);
		}
	}

}
