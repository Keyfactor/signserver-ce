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
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.openxml4j.samples.DemoCore;

/**
 * Demo : Extract all the parts of a package.
 * 
 * @author Julien Chable
 * @version 1.0
 */
public class ExtractListPartsZipOnly {

	private static DemoCore demoCore = new DemoCore();

	public static void main(String[] args) throws Exception {
		String filepath = demoCore.getTestRootPath() + "sample.pptx";
		System.out.println(String.format("Begining extraction at ... %1$s",
				System.getProperty("user.dir")));

		ZipFile zipFile = new ZipFile(filepath);
		Enumeration eEntries = zipFile.entries();
		while (eEntries.hasMoreElements()) {
			ZipEntry entry = (ZipEntry) eEntries.nextElement();

			System.out.println(String.format("Extracting %1$s ...", entry
					.getName()));
			extractEntryToFile(zipFile, entry);
			System.out.println(String.format("%1$s extracted !", entry
					.getName()));
		}

		System.out.println("Extraction finished !");
	}

	/**
	 * Extract a part to a file at the root of the application directory.
	 * 
	 * @param part
	 *            The part to extract.
	 */
	public static void extractEntryToFile(ZipFile zipFile, ZipEntry entry)
			throws Exception {
		String entryFilename = demoCore.getTestRootPath()
				+ entry.getName().substring(
						entry.getName().lastIndexOf("/") + 1);
		File f = new File(entryFilename);
		OutputStream outs = new FileOutputStream(f, false);
		InputStream ins = (zipFile.getInputStream(entry));

		byte[] buffer = new byte[2048];
		long count = 0;
		int n = 0;
		while (-1 != (n = ins.read(buffer))) {
			outs.write(buffer, 0, n);
			count += n;
		}

		ins.close();
		outs.flush();
		outs.close();
	}
}