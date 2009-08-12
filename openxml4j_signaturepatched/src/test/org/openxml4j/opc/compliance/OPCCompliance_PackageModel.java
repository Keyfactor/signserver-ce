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

package test.org.openxml4j.opc.compliance;

import java.io.File;

import junit.framework.TestCase;

import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.exceptions.InvalidOperationException;
import org.openxml4j.opc.ContentTypes;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackagePartName;
import org.openxml4j.opc.PackageRelationshipTypes;
import org.openxml4j.opc.PackagingURIHelper;
import org.openxml4j.opc.TargetMode;

import test.TestCore;

/**
 * Test Open Packaging Convention package model compliance.
 * 
 * M1.11 : A package implementer shall neither create nor recognize a part with
 * a part name derived from another part name by appending segments to it.
 * 
 * @author Julien Chable
 */
public class OPCCompliance_PackageModel extends TestCase {

	TestCore testCore = new TestCore(this.getClass());

	public OPCCompliance_PackageModel(String name) {
		super(name);
	}

	/**
	 * A package implementer shall neither create nor recognize a part with a
	 * part name derived from another part name by appending segments to it.
	 * [M1.11]
	 */
	public void testPartNameDerivationAdditionFailure() {
		Package pkg = null;
		try {
			pkg = Package.create("TODELETEIFEXIST.docx", true);
			PackagePartName name = PackagingURIHelper
					.createPartName("/word/document.xml");
			PackagePartName nameDerived = PackagingURIHelper
					.createPartName("/word/document.xml/image1.gif");
			pkg.createPart(name, ContentTypes.XML);
			pkg.createPart(nameDerived, ContentTypes.EXTENSION_GIF);
		} catch (InvalidOperationException e) {
			pkg.revert();
			return;
		} catch (InvalidFormatException e) {
			fail(e.getMessage());
		}
		fail("A package implementer shall neither create nor recognize a part with a"
				+ " part name derived from another part name by appending segments to it."
				+ " [M1.11]");
	}

	/**
	 * A package implementer shall neither create nor recognize a part with a
	 * part name derived from another part name by appending segments to it.
	 * [M1.11]
	 */
	public void testPartNameDerivationReadingFailure() {
		String filepath = testCore.getTestRootPath() + File.separator + "INPUT"
				+ File.separator + "OPCCompliance_DerivedPartNameFAIL.docx";
		try {
			Package.open(filepath);
		} catch (InvalidFormatException e) {
			return;
		}
		fail("A package implementer shall neither create nor recognize a part with a"
				+ " part name derived from another part name by appending segments to it."
				+ " [M1.11]");
	}

	/**
	 * Rule M1.12 : Packages shall not contain equivalent part names and package
	 * implementers shall neither create nor recognize packages with equivalent
	 * part names.
	 */
	public void testAddPackageAlreadyAddFailure() throws Exception {
		Package pkg = Package.create("DELETEIFEXISTS.docx", true);
		PackagePartName name1 = null;
		PackagePartName name2 = null;
		try {
			name1 = PackagingURIHelper.createPartName("/word/document.xml");
			name2 = PackagingURIHelper.createPartName("/word/document.xml");
		} catch (InvalidFormatException e) {
			throw new Exception(e.getMessage());
		}
		pkg.createPart(name1, ContentTypes.XML);
		try {
			pkg.createPart(name2, ContentTypes.XML);
		} catch (InvalidOperationException e) {
			return;
		}
		fail("Packages shall not contain equivalent part names and package implementers shall neither create nor recognize packages with equivalent part names. [M1.12]");
	}

	/**
	 * Rule M1.12 : Packages shall not contain equivalent part names and package
	 * implementers shall neither create nor recognize packages with equivalent
	 * part names.
	 */
	public void testAddPackageAlreadyAddFailure2() throws Exception {
		Package pkg = Package.create("DELETEIFEXISTS.docx", true);
		PackagePartName partName = null;
		try {
			partName = PackagingURIHelper.createPartName("/word/document.xml");
		} catch (InvalidFormatException e) {
			throw new Exception(e.getMessage());
		}
		pkg.createPart(partName, ContentTypes.XML);
		try {
			pkg.createPart(partName, ContentTypes.XML);
		} catch (InvalidOperationException e) {
			return;
		}
		fail("Packages shall not contain equivalent part names and package implementers shall neither create nor recognize packages with equivalent part names. [M1.12]");
	}

	/**
	 * Try to add a relationship to a relationship part.
	 * 
	 * Check rule M1.25: The Relationships part shall not have relationships to
	 * any other part. Package implementers shall enforce this requirement upon
	 * the attempt to create such a relationship and shall treat any such
	 * relationship as invalid.
	 */
	public void testAddRelationshipRelationshipsPartFailure() {
		Package pkg = Package.create("DELETEIFEXISTS.docx", true);
		PackagePartName name1 = null;
		try {
			name1 = PackagingURIHelper
					.createPartName("/test/_rels/document.xml.rels");
		} catch (InvalidFormatException e) {
			fail("This exception should never happen !");
		}

		try {
			pkg.addRelationship(name1, TargetMode.INTERNAL,
					PackageRelationshipTypes.CORE_DOCUMENT);
		} catch (InvalidOperationException e) {
			return;
		}
		fail("Fail test -> M1.25: The Relationships part shall not have relationships to any other part");
	}
}
