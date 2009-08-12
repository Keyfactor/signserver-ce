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
package test.junitx.framework;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.parsers.ParserConfigurationException;

import org.custommonkey.xmlunit.Diff;
import org.custommonkey.xmlunit.ElementNameAndAttributeQualifier;
import org.xml.sax.SAXException;

import junit.framework.Assert;
import junit.framework.AssertionFailedError;

/**
 * Compare the contents of 2 zip files.
 * 
 * @author CDubettier
 */
public class ZipFileAssert {
	private ZipFileAssert() {
	}

	static final int BUFFER_SIZE = 2048;

	protected static boolean equals(
			TreeMap<String, ByteArrayOutputStream> file1,
			TreeMap<String, ByteArrayOutputStream> file2) {
		Set listFile1 = file1.keySet();
		if (listFile1.size() == file2.keySet().size()) {
			for (Iterator iter = listFile1.iterator(); iter.hasNext();) {
				String fileName = (String) iter.next();
				// extract the contents for both
				ByteArrayOutputStream contain2 = file2.get(fileName);
				ByteArrayOutputStream contain1 = file1.get(fileName);

				if (contain2 == null) {
					// file not found in archive 2
					Assert.fail(fileName + " not found in 2nd zip");
					return false;
				}
				// no need to check for contain1. The key come from it

				if ((fileName.endsWith(".xml")) || fileName.endsWith(".rels")) {
					// we have a xml file
					try {
						String tst1 = contain2.toString().replaceAll(
								"[\t\n\r]+", "");
						String tst2 = contain1.toString().replaceAll(
								"[\t\n\r]+", "");
						// remove spaces between tags
						tst1 = tst1.replaceAll(">[ ]+<", "><");
						tst2 = tst2.replaceAll(">[ ]+<", "><");
						// we strip the CR LF as it will create extra nodes in
						// the parser
						// \t is used to indent the xml code. so nothing to do
						// except making it more human readable
						Diff myDiff = new Diff(tst1, tst2);
						myDiff
								.overrideElementQualifier(new ElementNameAndAttributeQualifier());
						if (!myDiff.similar()) {
							Assert.assertTrue(fileName + " XML NOT similar "
									+ myDiff.toString(), myDiff.similar());
						}
					} catch (SAXException e) {
						throw new AssertionFailedError(e.toString());
					} catch (IOException e) {
						throw new AssertionFailedError(e.toString());
					}
					// no more in new XMLUnit version
					// catch (ParserConfigurationException e) {
					// throw new AssertionFailedError(e.toString());
					// }
					catch (ParserConfigurationException e) {
						// TODO this exception is no longer thrown in latets
						// version of XmlUnit (from head)
						throw new AssertionFailedError(e.toString());
					}
				} else {
					// not xml, may be an image or other binary format
					if (contain2.size() != contain1.size()) {
						// not the same size
						Assert.fail(fileName
								+ " does not have the same size in both zip:"
								+ contain2.size() + "!=" + contain1.size());
						return false;
					}
					byte array1[] = contain1.toByteArray();
					byte array2[] = contain2.toByteArray();
					for (int i = 0; i < array1.length; i++) {
						if (array1[i] != array2[i]) {
							Assert.fail(fileName + " differ at index:" + i);
							return false;
						}
					}
				}
			}
		} else {
			// not the same number of files -> cannot be equals
			Assert.fail("not the same number of files in zip:"
					+ listFile1.size() + "!=" + file2.keySet().size());
			return false;
		}
		return true;
	}

	protected static TreeMap<String, ByteArrayOutputStream> decompress(
			File filename) throws IOException {
		// store the zip content in memory
		// let s assume it is not Go ;-)
		TreeMap<String, ByteArrayOutputStream> zipContent = new TreeMap<String, ByteArrayOutputStream>();

		byte data[] = new byte[BUFFER_SIZE];
		/* Open file to decompress */
		FileInputStream file_decompress = new FileInputStream(filename);

		/* Create a buffer for the decompressed files */
		BufferedInputStream buffi = new BufferedInputStream(file_decompress);

		/* Open the file with the buffer */
		ZipInputStream zis = new ZipInputStream(buffi);

		/* Processing entries of the zip file */
		ZipEntry entree;
		int count;
		while ((entree = zis.getNextEntry()) != null) {

			/* Create a array for the current entry */
			ByteArrayOutputStream byteArray = new ByteArrayOutputStream();
			zipContent.put(entree.getName(), byteArray);

			/* copy in memory */
			while ((count = zis.read(data, 0, BUFFER_SIZE)) != -1) {
				byteArray.write(data, 0, count);
			}
			/* Flush the buffer */
			byteArray.flush();
			byteArray.close();
		}

		zis.close();

		return zipContent;
	}

	/**
	 * Asserts that two files are equal. Throws an <tt>AssertionFailedError</tt>
	 * if they are not.
	 * <p>
	 * 
	 */
	public static void assertEquals(File expected, File actual) {
		Assert.assertNotNull(expected);
		Assert.assertNotNull(actual);

		Assert.assertTrue("File does not exist [" + expected.getAbsolutePath()
				+ "]", expected.exists());
		Assert.assertTrue("File does not exist [" + actual.getAbsolutePath()
				+ "]", actual.exists());

		Assert.assertTrue("Expected file not readable", expected.canRead());
		Assert.assertTrue("Actual file not readable", actual.canRead());

		try {
			TreeMap<String, ByteArrayOutputStream> file1 = decompress(expected);
			TreeMap<String, ByteArrayOutputStream> file2 = decompress(actual);
			equals(file1, file2);
		} catch (IOException e) {
			throw new AssertionFailedError(e.toString());
		}
	}
}
