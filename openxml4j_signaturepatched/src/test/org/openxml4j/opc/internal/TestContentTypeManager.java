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

package test.org.openxml4j.opc.internal;

import junit.framework.TestCase;

import org.openxml4j.opc.PackagePartName;
import org.openxml4j.opc.PackagingURIHelper;
import org.openxml4j.opc.internal.ContentTypeManager;
import org.openxml4j.opc.internal.ZipContentTypeManager;

import test.TestCore;

public class TestContentTypeManager extends TestCase {

	TestCore testCore = new TestCore(this.getClass());

	/**
	 * Test the properties part content parsing.
	 */
	public void testContentType() throws Exception {
		// File originalFile = new File(testCore.getTestRootPath() +
		// File.separator +
		// "sample.docx");
		//
		// // Retrieves core properties part
		// Package p = Package.open(originalFile.getAbsolutePath(),
		// PackageAccess.READ);
		// PackageRelationship corePropertiesRelationship = p
		// .getRelationshipsByType(
		// PackageRelationshipTypes.CORE_PROPERTIES)
		// .getRelationship(0);
		// PackagePart coreDocument = p.getPart(corePropertiesRelationship);
		//
		// ContentTypeManager ctm = new ZipContentTypeManager(coreDocument
		// .getInputStream());
		//
		// // TODO
		fail();
	}

	/**
	 * Test the addition of several default and override content types.
	 */
	public void testContentTypeAddition() throws Exception {
		ContentTypeManager ctm = new ZipContentTypeManager(null, null);

		PackagePartName name1 = PackagingURIHelper
				.createPartName("/foo/foo.XML");
		PackagePartName name2 = PackagingURIHelper
				.createPartName("/foo/foo2.xml");
		PackagePartName name3 = PackagingURIHelper
				.createPartName("/foo/doc.rels");
		PackagePartName name4 = PackagingURIHelper
				.createPartName("/foo/doc.RELS");

		// Add content types
		ctm.addContentType(name1, "foo-type1");
		ctm.addContentType(name2, "foo-type2");
		ctm.addContentType(name3, "text/xml+rel");
		ctm.addContentType(name4, "text/xml+rel");

		assertEquals(ctm.getContentType(name1), "foo-type1");
		assertEquals(ctm.getContentType(name2), "foo-type2");
		assertEquals(ctm.getContentType(name3), "text/xml+rel");
		assertEquals(ctm.getContentType(name3), "text/xml+rel");
	}

	/**
	 * Test the addition then removal of content types.
	 */
	public void testContentTypeRemoval() throws Exception {
		ContentTypeManager ctm = new ZipContentTypeManager(null, null);

		PackagePartName name1 = PackagingURIHelper
				.createPartName("/foo/foo.xml");
		PackagePartName name2 = PackagingURIHelper
				.createPartName("/foo/foo2.xml");
		PackagePartName name3 = PackagingURIHelper
				.createPartName("/foo/doc.rels");
		PackagePartName name4 = PackagingURIHelper
				.createPartName("/foo/doc.RELS");

		// Add content types
		ctm.addContentType(name1, "foo-type1");
		ctm.addContentType(name2, "foo-type2");
		ctm.addContentType(name3, "text/xml+rel");
		ctm.addContentType(name4, "text/xml+rel");
		ctm.removeContentType(name2);
		ctm.removeContentType(name3);

		assertEquals(ctm.getContentType(name1), "foo-type1");
		assertEquals(ctm.getContentType(name2), "foo-type1");
		assertEquals(ctm.getContentType(name3), null);

		ctm.removeContentType(name1);
		assertEquals(ctm.getContentType(name1), null);
		assertEquals(ctm.getContentType(name2), null);
	}

	/**
	 * Test the addition then removal of content types in a package.
	 */
	public void testContentTypeRemovalPackage() throws Exception {
		// TODO
	}
}
