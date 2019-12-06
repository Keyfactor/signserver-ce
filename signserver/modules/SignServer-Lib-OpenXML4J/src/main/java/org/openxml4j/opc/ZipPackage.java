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

package org.openxml4j.opc;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.apache.log4j.Logger;
import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.exceptions.InvalidOperationException;
import org.openxml4j.exceptions.OpenXML4JException;
import org.openxml4j.opc.internal.ContentTypeManager;
import org.openxml4j.opc.internal.FileHelper;
import org.openxml4j.opc.internal.MemoryPackagePart;
import org.openxml4j.opc.internal.PartMarshaller;
import org.openxml4j.opc.internal.ZipContentTypeManager;
import org.openxml4j.opc.internal.ZipHelper;
import org.openxml4j.opc.internal.marshallers.ZipPackagePropertiesMarshaller;
import org.openxml4j.opc.internal.marshallers.ZipPartMarshaller;
import org.openxml4j.util.ZipEntrySource;
import org.openxml4j.util.ZipFileZipEntrySource;
import org.openxml4j.util.ZipInputStreamZipEntrySource;

/**
 * Physical zip package.
 * 
 * @author Julien Chable
 * @version 0.2
 */
public final class ZipPackage extends Package {

	private static Logger logger = Logger.getLogger("org.openxml4j");

	/**
	 * Zip archive, as either a file on disk,
	 *  or a stream 
	 */
	private final ZipEntrySource zipArchive;

	/**
	 * Constructor. Creates a new ZipPackage.
	 */
	public ZipPackage() {
		super(defaultPackageAccess);
		this.zipArchive = null;
	}

	/**
	 * Constructor. <b>Operation not supported.</b>
	 * 
	 * @param in
	 *            Zip input stream to load.
	 * @param access
	 * @throws IllegalArgumentException
	 *             If the specified input stream not an instance of
	 *             ZipInputStream.
	 */
	ZipPackage(InputStream in, PackageAccess access) throws IOException {
		super(access);
		this.zipArchive = new ZipInputStreamZipEntrySource(
				new ZipInputStream(in)
		);
	}

	/**
	 * Constructor. Opens a Zip based Open XML document.
	 * 
	 * @param path
	 *            The path of the file to open or create.
	 * @param access
	 *            The package access mode.
	 * @throws InvalidFormatException
	 *             If the content type part parsing encounters an error.
	 */
	ZipPackage(String path, PackageAccess access) throws InvalidFormatException {
		super(access);
		
		ZipFile zipFile = ZipHelper.openZipFile(path);
		if (zipFile == null)
			throw new InvalidOperationException(
					"Can't open the specified file: '" + path + "'");
		this.zipArchive = new ZipFileZipEntrySource(zipFile); 
	}
	
	/**
	 * Retrieves the parts from this package. We assume that the package has not
	 * been yet inspect to retrieve all the parts, this method will open the
	 * archive and look for all parts contain inside it. If the package part
	 * list is not empty, it will be emptied.
	 * 
	 * @return All parts contain in this package.
	 * @throws InvalidFormatException
	 *             Throws if the package is not valid.
	 */
	@Override
	protected PackagePart[] getPartsImpl() throws InvalidFormatException {
		if (this.partCollection == null) {
			// The package has just been created, we create an empty part
			// list.
			this.partCollection = new PackagePartCollection();
		}

		if (this.zipArchive == null) {
			return this.partCollection.values().toArray(
					new PackagePart[this.partCollection.values().size()]);
		} else {
			// First we need to parse the content type part
			Enumeration<? extends ZipEntry> entries = this.zipArchive.getEntries();
			while (entries.hasMoreElements()) {
				ZipEntry entry = entries.nextElement();
				if (entry.getName().equals(
						ContentTypeManager.CONTENT_TYPES_PART_NAME)) {
					try {
						this.contentTypeManager = new ZipContentTypeManager(
								getZipArchive().getInputStream(entry), this);
					} catch (IOException e) {
						throw new InvalidFormatException(e.getMessage());
					}
					break;
				}
			}

			// At this point, we should have loaded the content type part
			if (this.contentTypeManager == null) {
				throw new InvalidFormatException(
						"Package should contain a content type part [M1.13]");
			}
			
			// Now create all the relationships
			// (Need to create relationships before other
			//  parts, otherwise we might create a part before
			//  its relationship exists, and then it won't tie up)
			entries = this.zipArchive.getEntries();
			while (entries.hasMoreElements()) {
				ZipEntry entry = (ZipEntry) entries.nextElement();
				PackagePartName partName = buildPartName(entry);
				if(partName == null) continue;
				
				// Only proceed for Relationships at this stage
				String contentType = contentTypeManager.getContentType(partName);
				if (contentType != null && contentType.equals(ContentTypes.RELATIONSHIPS_PART)) {
					try {
						partCollection.put(partName, new ZipPackagePart(this, entry,
							partName, contentType));
					} catch (InvalidOperationException e) {
						throw new InvalidFormatException(e.getMessage());
					}
				}
			}

			// Then we can go through all the other parts
			entries = this.zipArchive.getEntries();
			while (entries.hasMoreElements()) {
				ZipEntry entry = (ZipEntry) entries.nextElement();
				PackagePartName partName = buildPartName(entry);
				if(partName == null) continue;

				String contentType = contentTypeManager
						.getContentType(partName);
				if (contentType != null && contentType.equals(ContentTypes.RELATIONSHIPS_PART)) {
					// Already handled
				}
				else if (contentType != null) {
					try {
						partCollection.put(partName, new ZipPackagePart(this, entry,
								partName, contentType));
					} catch (InvalidOperationException e) {
						throw new InvalidFormatException(e.getMessage());
					}
				} else {
					throw new InvalidFormatException(
							"The part "
									+ partName.getURI().getPath()
									+ " does not have any content type ! Rule: Package require content types when retrieving a part from a package. [M.1.14]");
				}
			}
			
			return (ZipPackagePart[]) partCollection.values().toArray(
					new ZipPackagePart[partCollection.size()]);
		}
	}
	
	/**
	 * Builds a PackagePartName for the given ZipEntry,
	 *  or null if it's the content types / invalid part
	 */
	private PackagePartName buildPartName(ZipEntry entry) {
		try {
			// We get an error when we parse [Content_Types].xml
			// because it's not a valid URI.
			if (entry.getName().equals(
					ContentTypeManager.CONTENT_TYPES_PART_NAME)) {
				return null;
			} else {
				return PackagingURIHelper.createPartName(ZipHelper
						.getOPCNameFromZipItemName(entry.getName()));
			}
		} catch (Exception e) {
			// We assume we can continue, even in degraded mode ...
			logger.warn("Entry "
							+ entry.getName()
							+ " is not valid, so this part won't be add to the package.");
			return null;
		}
	}

	/**
	 * Create a new MemoryPackagePart from the specified URI and content type
	 * 
	 * 
	 * aram partName The part URI.
	 * 
	 * @param contentType
	 *            The part content type.
	 * @return The newly created zip package part, else <b>null</b>.
	 */
	@Override
	protected PackagePart createPartImpl(PackagePartName partName,
			String contentType, boolean loadRelationships) {
		if (contentType == null)
			throw new IllegalArgumentException("contentType");

		if (partName == null)
			throw new IllegalArgumentException("partName");

		try {
			return new MemoryPackagePart(this, partName, contentType,
					loadRelationships);
		} catch (InvalidFormatException e) {
			System.err.println(e);
			return null;
		}
	}

	/**
	 * Delete a part from the package
	 * 
	 * @throws IllegalArgumentException
	 *             Throws if the part URI is nulll or invalid.
	 */
	@Override
	protected void removePartImpl(PackagePartName partName) {
		if (partName == null)
			throw new IllegalArgumentException("partUri");
	}

	/**
	 * Flush the package. Do nothing.
	 */
	@Override
	protected void flushImpl() {
		// Do nothing
	}

	/**
	 * Close and save the package.
	 * 
	 * @see #close()
	 */
	@Override
	protected void closeImpl() throws IOException {
		// Flush the package
		flush();

		// Save the content
		if (this.originalPackagePath != null
				&& !"".equals(this.originalPackagePath)) {
			File targetFile = new File(this.originalPackagePath);
			if (targetFile.exists()) {
				// Case of a package previously open

				File tempFile = File.createTempFile(
						generateTempFileName(FileHelper
								.getDirectory(targetFile)), ".tmp");

				// Save the final package to a temporary file
				try {
					save(tempFile);
					this.zipArchive.close(); // Close the zip archive to be
					// able to delete it
					FileHelper.copyFile(tempFile, targetFile);
				} finally {
					// Either the save operation succeed or not, we delete the
					// temporary file
					if (!tempFile.delete()) {
						logger
								.warn("The temporary file: '"
										+ targetFile.getAbsolutePath()
										+ "' cannot be deleted ! Make sure that no other application use it.");
					}
				}
			} else {
				throw new InvalidOperationException(
						"Can't close a package not previously open with the open() method !");
			}
		}
	}

	/**
	 * Create a unique identifier to be use as a temp file name.
	 * 
	 * @return A unique identifier use to be use as a temp file name.
	 */
	private synchronized String generateTempFileName(File directory) {
		File tmpFilename;
		do {
			tmpFilename = new File(directory.getAbsoluteFile() + File.separator
					+ "OpenXML4J" + System.nanoTime());
		} while (tmpFilename.exists());
		return FileHelper.getFilename(tmpFilename.getAbsoluteFile());
	}

	/**
	 * Close the package without saving the document. Discard all the changes
	 * made to this package.
	 */
	@Override
	protected void revertImpl() {
		try {
			if (this.zipArchive != null)
				this.zipArchive.close();
		} catch (IOException e) {
			// Do nothing, user dont have to know
		}
	}

	/**
	 * Implement the getPart() method to retrieve a part from its URI in the
	 * current package
	 * 
	 * 
	 * @see #getPart(URI)
	 */
	@Override
	protected PackagePart getPartImpl(PackagePartName partName) {
		if (partCollection.containsKey(partName)) {
			return partCollection.get(partName);
		}
		return null;
	}

	/**
	 * Save this package into the specified stream
	 * 
	 * 
	 * @param outputStream
	 *            The stream use to save this package.
	 * 
	 * @see #save(OutputStream)
	 * @see #saveInZip(ZipOutputStream)
	 */
	@Override
	public void saveImpl(OutputStream outputStream) {
		// Check that the document was open in write mode
		throwExceptionIfReadOnly();
		ZipOutputStream zos = null;

		try {
			if (!(outputStream instanceof ZipOutputStream))
				zos = new ZipOutputStream(outputStream);
			else
				zos = (ZipOutputStream) outputStream;

			// If the core properties part does not exist in the part list,
			// we save it as well
			if (this.getPartsByRelationshipType(
					PackageRelationshipTypes.CORE_PROPERTIES).size() == 0) {
				logger.debug("Save core properties part");

				// We have to save the core properties part ...
				new ZipPackagePropertiesMarshaller().marshall(
						this.packageProperties, zos);
				// ... and to add its relationship ...
				this.relationships.addRelationship(this.packageProperties
						.getPartName().getURI(), TargetMode.INTERNAL,
						PackageRelationshipTypes.CORE_PROPERTIES, null);
				// ... and the content if it has not been added yet.
				if (!this.contentTypeManager
						.isContentTypeRegister(ContentTypes.CORE_PROPERTIES_PART)) {
					this.contentTypeManager.addContentType(
							this.packageProperties.getPartName(),
							ContentTypes.CORE_PROPERTIES_PART);
				}
			}

			// Save package relationships part.
			logger.debug("Save package relationships");
			ZipPartMarshaller.marshallRelationshipPart(this.getRelationships(),
					PackagingURIHelper.PACKAGE_RELATIONSHIPS_ROOT_PART_NAME,
					zos);

			// Save content type part.
			logger.debug("Save content types part");
			this.contentTypeManager.save(zos);

			// Save parts.
			for (PackagePart part : getParts()) {
				// If the part is a relationship part, we don't save it, it's
				// the source part that will do the job.
				if (part.isRelationshipPart())
					continue;

				logger.debug("Save part '"
						+ ZipHelper.getZipItemNameFromOPCName(part
								.getPartName().getName()) + "'");
				PartMarshaller marshaller = partMarshallers
						.get(part.contentType);
				if (marshaller != null) {
					if (!marshaller.marshall(part, zos)) {
						throw new OpenXML4JException(
								"The part "
										+ part.getPartName().getURI()
										+ " fail to be saved in the stream with marshaller "
										+ marshaller);
					}
				} else {
					if (!defaultPartMarshaller.marshall(part, zos))
						throw new OpenXML4JException(
								"The part "
										+ part.getPartName().getURI()
										+ " fail to be saved in the stream with marshaller "
										+ defaultPartMarshaller);
				}
			}
			zos.close();
		} catch (Exception e) {
			logger
					.error("Fail to save: an error occurs while saving the package : "
							+ e.getMessage());
		}
	}

	/**
	 * Get the zip archive
	 * 
	 * @return The zip archive.
	 */
	public ZipEntrySource getZipArchive() {
		return zipArchive;
	}
}
