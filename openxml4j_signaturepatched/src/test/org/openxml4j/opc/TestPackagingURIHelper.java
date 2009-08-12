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

package test.org.openxml4j.opc;

import java.net.URI;

import junit.framework.TestCase;

import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.opc.ContentTypes;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackagePartName;
import org.openxml4j.opc.PackagingURIHelper;

public class TestPackagingURIHelper extends TestCase {

	/**
	 * Test relativizePartName() method.
	 */
	public void testRelativizeURI() throws Exception {
		URI uri1 = new URI("/word/document.xml");
		URI uri2 = new URI("/word/media/image1.gif");

		// Document to image is down a directory
		URI retURI1to2 = PackagingURIHelper.relativizeURI(uri1, uri2);
		assertEquals("media/image1.gif", retURI1to2.getPath());
		// Image to document is up a directory
		URI retURI2to1 = PackagingURIHelper.relativizeURI(uri2, uri1);
		assertEquals("../document.xml", retURI2to1.getPath());

		// Document and CustomXML parts totally different [Julien C.]
		URI uriCustomXml = new URI("/customXml/item1.xml");
		URI uriRes = PackagingURIHelper.relativizeURI(uri1, uriCustomXml);
		assertEquals("../customXml/item1.xml", uriRes.toString());

		// Document to itself is the same place (empty URI)
		URI retURI2 = PackagingURIHelper.relativizeURI(uri1, uri1);
		assertEquals("", retURI2.getPath());

		// Document and root totally different
		URI uri4 = new URI("/");
		try {
			PackagingURIHelper.relativizeURI(uri1, uri4);
			fail("Must throw an exception ! Can't relativize with an empty URI");
		} catch (Exception e) {
			// Do nothing
		}
		try {
			PackagingURIHelper.relativizeURI(uri4, uri1);
			fail("Must throw an exception ! Can't relativize with an empty URI");
		} catch (Exception e) {
			// Do nothing
		}
	}

	/**
	 * Test createPartName(String, y)
	 */
	public void testCreatePartNameRelativeString()
			throws InvalidFormatException {
		PackagePartName partNameToValid = PackagingURIHelper
				.createPartName("/word/media/image1.gif");

		Package pkg = Package.create("DELETEIFEXISTS.docx", true);
		// Base part
		PackagePartName nameBase = PackagingURIHelper
				.createPartName("/word/document.xml");
		PackagePart partBase = pkg.createPart(nameBase, ContentTypes.XML);
		// Relative part name
		PackagePartName relativeName = PackagingURIHelper.createPartName(
				"media/image1.gif", partBase);
		assertTrue("The part name must be equal to "
				+ partNameToValid.getName(), partNameToValid
				.equals(relativeName));
		pkg.revert();
	}

	/**
	 * Test createPartName(URI, y)
	 */
	public void testCreatePartNameRelativeURI() throws Exception {
		PackagePartName partNameToValid = PackagingURIHelper
				.createPartName("/word/media/image1.gif");

		Package pkg = Package.create("DELETEIFEXISTS.docx", true);
		// Base part
		PackagePartName nameBase = PackagingURIHelper
				.createPartName("/word/document.xml");
		PackagePart partBase = pkg.createPart(nameBase, ContentTypes.XML);
		// Relative part name
		PackagePartName relativeName = PackagingURIHelper.createPartName(
				new URI("media/image1.gif"), partBase);
		assertTrue("The part name must be equal to "
				+ partNameToValid.getName(), partNameToValid
				.equals(relativeName));
		pkg.revert();
	}

	/**
	 * Test the createPackURIFromPartName method.
	 */
	public void testCreatePackURIFromPartName() throws Exception {
		PackagePartName partName = PackagePartName.createPartName("/a/b/foo.xml");
		URI baseURI = new URI("http://www.openxmlformats.org/my.container");
		String testPackURI = PackagingURIHelper.createPackURIFromPartName(baseURI, partName);
		assertTrue(
				"The pack URI must be equals pack://http%3c,,www.openxmlformats.org,my.container/a/b/foo.xml",
				"pack://http%3a,,www.openxmlformats.org,my.container/a/b/foo.xml".equals(testPackURI));
	}
	
	/**
	 * Test the resolvePackURI method.
	 */
	public void testResolvePackURI() throws Exception {
		String testPackURI = "pack://http%3a,,www.my.com,packages.aspx%3fmy.package/a/b/foo.xml";
		
		URI packageUri = null;
		PackagePartName partName = null;
		PackagingURIHelper.resolvePackURI(testPackURI, packageUri, partName);
		
		// Test
		PackagePartName resPartName1 = PackagingURIHelper.createPartName("/a/b/foo.xml");
		String resPackageURI = "http://www.my.com/packages.aspx?my.package";
		assertTrue(resPartName1.equals(partName));
		assertTrue(resPackageURI.equals(packageUri));
	}
}
