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

import junit.framework.TestCase;

import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.opc.internal.ContentType;

/**
 * Tests for content type (ContentType class).
 * 
 * @author Julien Chable
 */
public class TestContentType extends TestCase {

	/**
	 * Check rule M1.13: Package implementers shall only create and only
	 * recognize parts with a content type; format designers shall specify a
	 * content type for each part included in the format. Content types for
	 * package parts shall fit the definition and syntax for media types as
	 * specified in RFC 2616,аз3.7.
	 */
	public void testContentTypeValidation() throws InvalidFormatException {
		String[] contentTypesToTest = new String[] { "text/xml",
				"application/pgp-key", "application/vnd.hp-PCLXL",
				"application/vnd.lotus-1-2-3" };
		for (int i = 0; i < contentTypesToTest.length; ++i) {
			new ContentType(contentTypesToTest[i]);
		}
	}

	/**
	 * Check rule M1.13 : Package implementers shall only create and only
	 * recognize parts with a content type; format designers shall specify a
	 * content type for each part included in the format. Content types for
	 * package parts shall fit the definition and syntax for media types as
	 * specified in RFC 2616,аз3.7.
	 * 
	 * Check rule M1.14: Content types shall not use linear white space either
	 * between the type and subtype or between an attribute and its value.
	 * Content types also shall not have leading or trailing white spaces.
	 * Package implementers shall create only such content types and shall
	 * require such content types when retrieving a part from a package; format
	 * designers shall specify only such content types for inclusion in the
	 * format.
	 */
	public void testContentTypeValidationFailure() {
		String[] contentTypesToTest = new String[] { "text/xml/app", "",
				"test", "text(xml/xml", "text)xml/xml", "text<xml/xml",
				"text>/xml", "text@/xml", "text,/xml", "text;/xml",
				"text:/xml", "text\\/xml", "t/ext/xml", "t\"ext/xml",
				"text[/xml", "text]/xml", "text?/xml", "tex=t/xml",
				"te{xt/xml", "tex}t/xml", "te xt/xml",
				"text" + (char) 9 + "/xml", "text xml", " text/xml " };
		for (int i = 0; i < contentTypesToTest.length; ++i) {
			try {
				new ContentType(contentTypesToTest[i]);
			} catch (InvalidFormatException e) {
				continue;
			}
			fail("Must have fail for content type: '" + contentTypesToTest[i]
					+ "' !");
		}
	}

	/**
	 * Check rule [O1.2]: Format designers might restrict the usage of
	 * parameters for content types.
	 */
	public void testContentTypeParameterFailure() {
		String[] contentTypesToTest = new String[] { "mail/toto;titi=tata",
				"text/xml;a=b;c=d", "mail/toto;\"titi=tata\"" };
		for (int i = 0; i < contentTypesToTest.length; ++i) {
			try {
				new ContentType(contentTypesToTest[i]);
			} catch (InvalidFormatException e) {
				continue;
			}
			fail("Must have fail for content type: '" + contentTypesToTest[i]
					+ "' !");
		}
	}

	/**
	 * Check rule M1.15: The package implementer shall require a content type
	 * that does not include comments and the format designer shall specify such
	 * a content type.
	 */
	public void testContentTypeCommentFailure() {
		String[] contentTypesToTest = new String[] { "text/xml(comment)" };
		for (int i = 0; i < contentTypesToTest.length; ++i) {
			try {
				new ContentType(contentTypesToTest[i]);
			} catch (InvalidFormatException e) {
				continue;
			}
			fail("Must have fail for content type: '" + contentTypesToTest[i]
					+ "' !");
		}
	}
}
