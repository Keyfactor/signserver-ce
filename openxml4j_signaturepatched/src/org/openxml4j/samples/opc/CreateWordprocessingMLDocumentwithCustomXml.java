/*
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
import java.net.URI;

import org.dom4j.Document;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.Namespace;
import org.dom4j.QName;
import org.openxml4j.opc.ContentTypes;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackagePartName;
import org.openxml4j.opc.PackageRelationshipTypes;
import org.openxml4j.opc.PackagingURIHelper;
import org.openxml4j.opc.StreamHelper;
import org.openxml4j.opc.TargetMode;
import org.openxml4j.samples.DemoCore;

/**
 * Creates a WordprocessingML document from scratch using only the OPC part of
 * OpenXML4J.
 * 
 * @author Julien Chable
 * @version 0.1
 */
public class CreateWordprocessingMLDocumentwithCustomXml {

	public static void main(String[] args) throws Exception {
		DemoCore demoCore = new DemoCore();

		File outputDocument = new File(demoCore.getTestRootPath()
				+ "sample_output.docx");

		// Create a package
		Package pkg = Package.create(outputDocument, true);

		// --- Add the main part (WorprocessingML document) ---

		PackagePartName corePartName = PackagingURIHelper
				.createPartName("/word/document.xml");

		// Create main part relationship
		pkg.addRelationship(corePartName, TargetMode.INTERNAL,
				PackageRelationshipTypes.CORE_DOCUMENT, "rId1");

		// Create main document part
		PackagePart corePart = pkg
				.createPart(
						corePartName,
						"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml");

		// Create main document part content
		Document doc = DocumentHelper.createDocument();
		Namespace nsWordprocessinML = new Namespace("w",
				"http://schemas.openxmlformats.org/wordprocessingml/2006/main");
		Element elDocument = doc.addElement(new QName("document",
				nsWordprocessinML));
		Element elBody = elDocument.addElement(new QName("body",
				nsWordprocessinML));
		Element elParagraph = elBody.addElement(new QName("p",
				nsWordprocessinML));
		Element elRun = elParagraph
				.addElement(new QName("r", nsWordprocessinML));
		Element elText = elRun.addElement(new QName("t", nsWordprocessinML));
		elText.setText("Hello Open XML !");

		// Save the XML structure into the part
		StreamHelper.saveXmlInStream(doc, corePart.getOutputStream());

		// --- Add the custom XML part ---

		// Create part
		PackagePartName customXmlPartName = PackagingURIHelper
				.createPartName("/customXml/item1.xml");
		pkg.createPart(customXmlPartName, ContentTypes.CUSTOM_XML_PART);

		// Add relationship
		URI relativeCustomXmlPartURI = PackagingURIHelper.relativizeURI(
				corePartName.getURI(), customXmlPartName.getURI());
		corePart.addRelationship(relativeCustomXmlPartURI, TargetMode.INTERNAL,
				PackageRelationshipTypes.CUSTOM_XML);
		
		// Create Custom XML document part content
		Document customXmlDoc = DocumentHelper.createDocument();
		Element elCustomer = customXmlDoc.addElement(new QName("customer",
				nsWordprocessinML));
		Element elName = elCustomer.addElement(new QName("name", nsWordprocessinML));
		elName.setText("Leonarde Da Vinci");

		// Save the XML structure into the part
		StreamHelper.saveXmlInStream(customXmlDoc, corePart.getOutputStream());

		// Save package
		pkg.close();
	}
}
