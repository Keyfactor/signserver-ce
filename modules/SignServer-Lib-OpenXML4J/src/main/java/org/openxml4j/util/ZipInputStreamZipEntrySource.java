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
package org.openxml4j.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Provides a way to get at all the ZipEntries
 *  from a ZipInputStream, as many times as required.
 * Allows a ZipInputStream to be treated much like
 *  a ZipFile, for a price in terms of memory.
 * Be sure to call {@link #close()} as soon as you're
 *  done, to free up that memory!
 */
public class ZipInputStreamZipEntrySource implements ZipEntrySource {
	private ArrayList<FakeZipEntry> zipEntries;
	
	/**
	 * Reads all the entries from the ZipInputStream 
	 *  into memory, and closes the source stream.
	 * We'll then eat lots of memory, but be able to
	 *  work with the entries at-will.
	 */
	public ZipInputStreamZipEntrySource(ZipInputStream inp) throws IOException {
		zipEntries = new ArrayList<FakeZipEntry>();
		
		boolean going = true;
		while(going) {
			ZipEntry zipEntry = inp.getNextEntry();
			if(zipEntry == null) {
				going = false;
			} else {
				FakeZipEntry entry = new FakeZipEntry(zipEntry, inp);
				inp.closeEntry();
				
				zipEntries.add(entry);
			}
		}
		inp.close();
	}

	public Enumeration<? extends ZipEntry> getEntries() {
		return new EntryEnumerator();
	}
	
	public InputStream getInputStream(ZipEntry zipEntry) {
		FakeZipEntry entry = (FakeZipEntry)zipEntry;
		return entry.getInputStream();
	}
	
	public void close() {
		// Free the memory
		zipEntries = null;
	}
	
	/**
	 * Why oh why oh why are Iterator and Enumeration
	 *  still not compatible?
	 */
	private class EntryEnumerator implements Enumeration<ZipEntry> {
		private Iterator<? extends ZipEntry> iterator;
		
		private EntryEnumerator() {
			iterator = zipEntries.iterator();
		}
		
		public boolean hasMoreElements() {
			return iterator.hasNext();
		}

		public ZipEntry nextElement() {
			return iterator.next();
		}
	}

	/**
	 * So we can close the real zip entry and still
	 *  effectively work with it.
	 * Holds the (decompressed!) data in memory, so
	 *  close this as soon as you can! 
	 */
	public static class FakeZipEntry extends ZipEntry {
		private byte[] data;
		
		public FakeZipEntry(ZipEntry entry, ZipInputStream inp) throws IOException {
			super(entry.getName());
			
			// Grab the de-compressed contents for later
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] buffer = new byte[4096];
			int read = 0;
			while( (read = inp.read(buffer)) != -1 ) {
				baos.write(buffer, 0, read);
			}
			
			data = baos.toByteArray();
		}
		
		public InputStream getInputStream() {
			return new ByteArrayInputStream(data);
		}
	}
}
