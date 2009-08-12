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

import java.io.InputStream;

import org.dom4j.Document;
import org.dom4j.io.SAXReader;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackageAccess;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackageRelationship;
import org.openxml4j.opc.PackageRelationshipTypes;
import org.openxml4j.samples.DemoCore;

/**
 * Read extended properties from an OPC document.
 * 
 * @author Julien Chable, CDubet
 * @version 1.0
 */
public class ListingExtractDocumentExtendedProperties {

	public static void main(String[] args) {
		DemoCore demoCore = new DemoCore();

		// Open the package
		Package p;
		try {
			p = Package.open(demoCore.getTestRootPath() + "sample.docx",
					PackageAccess.READ);

			// Retrieves extended properties part relationship
			PackageRelationship extendedPropertiesRelationship = p
					.getRelationshipsByType(
							PackageRelationshipTypes.EXTENDED_PROPERTIES)
					.getRelationship(0);

			// Retrieves extended properties part
			PackagePart extPropsPart = p
					.getPart(extendedPropertiesRelationship);
			System.out.println(extPropsPart.getPartName() + " -> "
					+ extPropsPart.getContentType());

			// Get the input stream from the extended properties part
			InputStream inStream = extPropsPart.getInputStream();

			// Parse the XML content
			SAXReader xmlReader = new SAXReader();
			Document extPropsDoc = xmlReader.read(inStream);

			// Print some values
			System.out.println("Document generated with "
					+ extPropsDoc.getRootElement().element("Application")
							.getStringValue()
					+ " version "
					+ extPropsDoc.getRootElement().element("AppVersion")
							.getStringValue());

			// Print more values
			System.out.println("The document have "
					+ extPropsDoc.getRootElement().element("Words")
							.getStringValue()
					+ " words  "
					+ extPropsDoc.getRootElement().element("Characters")
							.getStringValue()
					+ " charaters, and "
					+ extPropsDoc.getRootElement().element("Lines")
							.getStringValue() + " lines");

			inStream.close();
		} catch (Exception ioe) {
			System.err
					.println("Fail to extract application properties of the document ! :(");
		}
	}
}
