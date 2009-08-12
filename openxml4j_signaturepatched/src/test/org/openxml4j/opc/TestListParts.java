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

import java.io.File;
import java.util.TreeMap;

import junit.framework.TestCase;

import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackageAccess;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackagePartName;
import org.openxml4j.opc.PackagingURIHelper;

import test.TestCore;

public class TestListParts extends TestCase {

	TestCore testCore = new TestCore(this.getClass());

	TreeMap<PackagePartName, String> expectedValues;

	TreeMap<PackagePartName, String> values;

	@Override
	protected void setUp() throws Exception {
		values = new TreeMap<PackagePartName, String>();

		// Expected values
		expectedValues = new TreeMap<PackagePartName, String>();
		expectedValues.put(PackagingURIHelper.createPartName("/_rels/.rels"),
				"application/vnd.openxmlformats-package.relationships+xml");

		expectedValues
				.put(PackagingURIHelper.createPartName("/docProps/app.xml"),
						"application/vnd.openxmlformats-officedocument.extended-properties+xml");
		expectedValues.put(PackagingURIHelper
				.createPartName("/docProps/core.xml"),
				"application/vnd.openxmlformats-package.core-properties+xml");
		expectedValues.put(PackagingURIHelper
				.createPartName("/word/_rels/document.xml.rels"),
				"application/vnd.openxmlformats-package.relationships+xml");
		expectedValues
				.put(
						PackagingURIHelper.createPartName("/word/document.xml"),
						"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml");
		expectedValues
				.put(PackagingURIHelper.createPartName("/word/fontTable.xml"),
						"application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml");
		expectedValues.put(PackagingURIHelper
				.createPartName("/word/media/image1.gif"), "image/gif");
		expectedValues
				.put(PackagingURIHelper.createPartName("/word/settings.xml"),
						"application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml");
		expectedValues
				.put(PackagingURIHelper.createPartName("/word/styles.xml"),
						"application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml");
		expectedValues.put(PackagingURIHelper
				.createPartName("/word/theme/theme1.xml"),
				"application/vnd.openxmlformats-officedocument.theme+xml");
		expectedValues
				.put(
						PackagingURIHelper
								.createPartName("/word/webSettings.xml"),
						"application/vnd.openxmlformats-officedocument.wordprocessingml.webSettings+xml");
	}

	/**
	 * List all parts of a package.
	 */
	public void testListParts() throws InvalidFormatException {
		String filepath = testCore.getTestRootPath() + "INPUT" + File.separator
				+ "sample.docx";

		Package p = Package.open(filepath, PackageAccess.READ);
		for (PackagePart part : p.getParts()) {
			values.put(part.getPartName(), part.getContentType());
			System.out.println(part.getPartName());
		}

		// Compare expected values with values return by the package
		for (PackagePartName partName : expectedValues.keySet()) {
			assertNotNull(values.get(partName));
			assertEquals(expectedValues.get(partName), values.get(partName));
		}
	}
}
