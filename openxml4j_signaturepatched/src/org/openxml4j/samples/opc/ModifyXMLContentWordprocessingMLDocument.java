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

package org.openxml4j.samples.opc;

import java.io.File;
import java.io.InputStream;
import java.util.List;

import org.dom4j.Document;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.Namespace;
import org.dom4j.QName;
import org.dom4j.io.SAXReader;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackageAccess;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackageRelationship;
import org.openxml4j.opc.PackageRelationshipTypes;
import org.openxml4j.opc.StreamHelper;
import org.openxml4j.samples.DemoCore;

/**
 * Modify the content of a package by retrieving the main document part and
 * modifying its content.
 * 
 * @author Julien Chable
 * @version 0.1
 */
public class ModifyXMLContentWordprocessingMLDocument {

	@SuppressWarnings("unchecked")
	public static void main(String[] args) throws Exception {
		DemoCore demoCore = new DemoCore();

		// Open the package
		Package pkg = Package.open(demoCore.getTestRootPath() + "sample.docx",
				PackageAccess.READ_WRITE);

		// Get documents core document part relationship
		PackageRelationship coreDocumentRelationship = pkg
				.getRelationshipsByType(PackageRelationshipTypes.CORE_DOCUMENT)
				.getRelationship(0);

		// Get core document part from the relationship.
		PackagePart coreDocumentPart = pkg.getPart(coreDocumentRelationship);

		InputStream inStream = coreDocumentPart.getInputStream();
		SAXReader docReader = new SAXReader();
		Document doc = docReader.read(inStream);

		Namespace namespaceWordProcessingML = new Namespace("w",
				"http://schemas.openxmlformats.org/wordprocessingml/2006/main");
		Element bodyElement = doc.getRootElement().element(
				new QName("body", namespaceWordProcessingML));

		// Retrieves paragraph childs from body element
		List paragraphs = bodyElement.content();

		// Build a new paragraph element
		Element paragraph = DocumentHelper.createElement(new QName("p",
				namespaceWordProcessingML));
		Element run = paragraph.addElement(new QName("r",
				namespaceWordProcessingML));
		Element text = run
				.addElement(new QName("t", namespaceWordProcessingML));
		text.setText("New paragraph added with OpenXML4J !");

		// Add the newly created paragraph at the last position of paragraph
		// elements, just before the w:sectPr element
		paragraphs.add(paragraphs.size() - 1, paragraph);

		// Save back the content into the part
		StreamHelper.saveXmlInStream(doc, coreDocumentPart.getOutputStream());

		pkg.save(new File(demoCore.getTestRootPath() + "sample_output.docx"));
	}
}
