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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.apache.log4j.Logger;
import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.exceptions.InvalidOperationException;
import org.openxml4j.exceptions.OpenXML4JException;
import org.openxml4j.exceptions.OpenXML4JRuntimeException;
import org.openxml4j.opc.internal.ContentType;
import org.openxml4j.opc.internal.ContentTypeManager;
import org.openxml4j.opc.internal.PackagePropertiesPart;
import org.openxml4j.opc.internal.PartMarshaller;
import org.openxml4j.opc.internal.PartUnmarshaller;
import org.openxml4j.opc.internal.ZipContentTypeManager;
import org.openxml4j.opc.internal.marshallers.DefaultMarshaller;
import org.openxml4j.opc.internal.marshallers.ZipPackagePropertiesMarshaller;
import org.openxml4j.opc.internal.unmarshallers.PackagePropertiesUnmarshaller;
import org.openxml4j.opc.internal.unmarshallers.UnmarshallContext;
import org.openxml4j.util.Nullable;

/**
 * Represents a container that can store multiple data objects.
 * 
 * @author Julien Chable, CDubet
 * @version 0.9
 */
public abstract class Package implements RelationshipSource {

	/**
	 * Logger.
	 */
	protected static Logger logger;

	/**
	 * Default package access.
	 */
	protected static final PackageAccess defaultPackageAccess = PackageAccess.READ_WRITE;

	// Static initialization
	static 
	{
		try
		{
			logger = Logger.getLogger("org.openxml4j.opc");
		} 
		catch (Exception e)
		{
			// Do nothing
		}
	}
	
	/**
	 * Package access.
	 */
	private PackageAccess packageAccess;

	/**
	 * Package parts collection.
	 */
	protected PackagePartCollection partCollection;

	/**
	 * Package relationships.
	 */
	protected PackageRelationshipCollection relationships;

	/**
	 * Part marshallers by content type.
	 */
	protected Hashtable<ContentType, PartMarshaller> partMarshallers;

	/**
	 * Default part marshaller.
	 */
	protected PartMarshaller defaultPartMarshaller;

	/**
	 * Part unmarshallers by content type.
	 */
	protected Hashtable<ContentType, PartUnmarshaller> partUnmarshallers;

	/**
	 * Core package properties.
	 */
	protected PackagePropertiesPart packageProperties;

	/**
	 * Manage parts content types of this package.
	 */
	protected ContentTypeManager contentTypeManager;

	/**
	 * Flag if a modification is done to the document.
	 */
	protected boolean isDirty = false;

	/**
	 * File path of this package.
	 */
	protected String originalPackagePath;

	/**
	 * Output stream for writing this package.
	 */
	protected OutputStream output;

	/**
	 * Constructor.
	 * 
	 * @param access
	 *            Package access.
	 */
	protected Package(PackageAccess access) {
		init();
		this.packageAccess = access;
	}

	/**
	 * Initialize the package instance.
	 */
	private void init() {
		this.partMarshallers = new Hashtable<ContentType, PartMarshaller>(5);
		this.partUnmarshallers = new Hashtable<ContentType, PartUnmarshaller>(2);

		try {
			// Add 'default' unmarshaller
			this.partUnmarshallers.put(new ContentType(
					ContentTypes.CORE_PROPERTIES_PART),
					new PackagePropertiesUnmarshaller());

			// Add default marshaller
			this.defaultPartMarshaller = new DefaultMarshaller();
			// TODO Delocalize specialized marshallers
			this.partMarshallers.put(new ContentType(
					ContentTypes.CORE_PROPERTIES_PART),
					new ZipPackagePropertiesMarshaller());
		} catch (InvalidFormatException e) {
			// Should never happpen
			throw new OpenXML4JRuntimeException(
					"Package.init() : this exception should never happen, if you read this message please send a mail to the developers team.");
		}
	}

	/**
	 * Open a package with read/write permission.
	 * 
	 * @param path
	 *            The document path.
	 * @return A Package object, else <b>null</b>.
	 * @throws InvalidFormatException
	 *             If the specified file doesn't exist, and a parsing error
	 *             occur.
	 */
	public static Package open(String path) throws InvalidFormatException {
		return open(path, defaultPackageAccess);
	}

	/**
	 * Open a package.
	 * 
	 * @param path
	 *            The document path.
	 * @param access
	 *            Package access.
	 * @return A Package object, else <b>null</b>.
	 * @throws InvalidFormatException
	 *             If the specified file doesn't exist, and a parsing error
	 *             occur.
	 */
	public static Package open(String path, PackageAccess access)
			throws InvalidFormatException {
		if (path == null || "".equals(path.trim())
				|| (new File(path).exists() && new File(path).isDirectory()))
			throw new IllegalArgumentException("path");

		Package pack = new ZipPackage(path, access);
		if (pack.partCollection == null && access != PackageAccess.WRITE) {
			pack.getParts();
		}
		pack.originalPackagePath = new File(path).getAbsolutePath();
		return pack;
	}
	
	/**
	 * open a package
	 * 
	 * @param in 
	 * 			The document stream
	 * @param access
	 * 			Package access
	 * @return
	 * 			A Package object
	 * @throws InvalidFormatException
	 * @throws IOException
	 */
	public static Package open(InputStream in, PackageAccess access)
			throws InvalidFormatException, IOException {
		Package pack = new ZipPackage(in, access);
		if (pack.partCollection == null) {
			pack.getParts();
		}
		return pack;
	}


	/**
	 * Open a package.
	 * 
	 * Note - uses quite a bit more memory than {@link #open(String)}, which
	 * doesn't need to hold the whole zip file in memory, and can take advantage
	 * of native methods
	 * 
	 * @param in
	 *            The InputStream to read the package from
	 * @return A Package object
	 */
	public static Package open(InputStream in) throws InvalidFormatException,
			IOException {
		Package pack = new ZipPackage(in, PackageAccess.READ);
		if (pack.partCollection == null) {
			pack.getParts();
		}
		return pack;
	}

	/**
	 * Opens a package if it exists, else it creates one. If the specified file
	 * already exists, it WON'T be overwritten. 
	 * 
	 * @param file
	 *            The file to open or to create.
	 * @return A newly created package if the specified file does not exist,
	 *         else the package extract from the file.
	 * @throws InvalidFormatException
	 *             Throws if the specified file exist and is not valid.
	 * @see #create(File, boolean)
	 */
	public static Package openOrCreate(File file) throws InvalidFormatException {
		Package retPackage = null;
		if (file.exists()) {
			retPackage = open(file.getAbsolutePath());
		} else {
			retPackage = create(file, false);
		}
		return retPackage;
	}

	/**
	 * Creates a new package. If the file already exist, it will be
	 * overwritten by the new one.
	 * 
	 * @param path
	 *            Path of the document.
	 * @return A newly created Package ready to use.
	 * @see #create(String, boolean)
	 */
	public static Package create(String path) {
		return create(new File(path), true);
	}
	
	/**
	 * Creates a new package.
	 * 
	 * @param path
	 *            Path of the document.
	 * @param overwrite
	 *            Flag to allow overwriting of the specified file.
	 * @return A newly created Package ready to use.
	 */
	public static Package create(String path, boolean overwrite) {
		return create(new File(path), overwrite);
	}

	/**
	 * Creates a new package.
	 * 
	 * @param file
	 *            Path of the document. Must not be null.
	 * @param overwrite
	 *            Flag to allow overwriting of the specified file.
	 * @return A newly created Package ready to use or <i>null</i> if the
	 *         method was unable to create a package at the specified location.
	 */
	public static Package create(File file, boolean overwrite) {
		if (file == null || (file.exists() && file.isDirectory()))
			throw new IllegalArgumentException("file");

		// Check for the existence of the file. Overwrite not allowed.
		if (file.exists() && !overwrite) {
			throw new InvalidOperationException(
					"This package (or file) already exists : use the open() method or delete the file.");
		} else if (file.exists() && overwrite) {
			logger.info(String.format("The file '%1$s' will be overwritten.",
					file.getAbsolutePath()));
		}

		// Creates a new package
		Package retPackage = null;
		retPackage = new ZipPackage();
		retPackage.originalPackagePath = file.getAbsolutePath();

		// Creates the file
//		try {
//			if (file.exists())
//				retPackage.output = new FileOutputStream(file, false);
//			else {
//				file.createNewFile();
//				retPackage.output = new FileOutputStream(file);
//			}
//		} catch (IOException ioe) {
//			logger.error(String.format(
//					"Can't create a package at '%1$s': %2$s", file
//							.getAbsolutePath(), ioe.getMessage()));
//			return null;
//		}

		// Initialize the package stuff ...
		configurePackage(retPackage);
		return retPackage;
	}

	/**
	 * Creates a new package.
	 * 
	 * @param output
	 *            The output stream where to write the package.
	 * @return A newly created Package object.
	 */
	public static Package create(OutputStream output) {
		Package pkg = null;
		pkg = new ZipPackage();
		pkg.originalPackagePath = null;
		pkg.output = output;

		configurePackage(pkg);
		return pkg;
	}

	/**
	 * Configure the package.
	 * 
	 * @param pkg
	 *            The package to configure.
	 */
	private static void configurePackage(Package pkg) {
		try {
			// Content type manager
			pkg.contentTypeManager = new ZipContentTypeManager(null, pkg);
			// Add default content types for .xml and .rels
			pkg.contentTypeManager
					.addContentType(
							PackagingURIHelper
									.createPartName(PackagingURIHelper.PACKAGE_RELATIONSHIPS_ROOT_URI),
							ContentTypes.RELATIONSHIPS_PART);
			pkg.contentTypeManager
					.addContentType(PackagingURIHelper
							.createPartName("/default.xml"),
							ContentTypes.PLAIN_OLD_XML);

			// Initialize some Package properties
			pkg.packageProperties = new PackagePropertiesPart(pkg,
					PackagingURIHelper.CORE_PROPERTIES_PART_NAME);
			pkg.packageProperties.setCreatorProperty("Generated by OpenXML4J");
			pkg.packageProperties.setCreatedProperty(new Nullable<Date>(
					new Date()));
		} catch (InvalidFormatException e) {
			// Should never happen
			throw new IllegalStateException(e);
		}
	}

	/**
	 * Flush the package : save all.
	 * 
	 * @see #close()
	 */
	public void flush() {
		throwExceptionIfReadOnly();

		if (this.packageProperties != null)
			((PackagePropertiesPart) this.packageProperties).flush();

		this.flushImpl();
	}

	/**
	 * Close the package and save its content.
	 * 
	 * @throws IOException
	 *             If an IO exception occur during the saving process.
	 */
	public void close() throws IOException {
		if (this.packageAccess == PackageAccess.READ) {
			logger
					.warn("The close() method is intended to SAVE a package. This package is open in READ ONLY mode, use the revert() method instead !");
			return;
		}

		// Save the content
		ReentrantReadWriteLock l = new ReentrantReadWriteLock();
		try {
			l.writeLock().lock();
			if (this.originalPackagePath != null
					&& !"".equals(this.originalPackagePath.trim())) {
				File targetFile = new File(this.originalPackagePath);
				if (!targetFile.exists()
						|| !(this.originalPackagePath
								.equalsIgnoreCase(targetFile.getAbsolutePath()))) {
					// Case of a package created from scratch
					save(targetFile);
				} else {
					closeImpl();
				}
			} else if (this.output != null) {
				save(this.output);
			}
		} finally {
			l.writeLock().unlock();
		}

		// Clear
		this.contentTypeManager.clearAll();

		// Call the garbage collector
		Runtime.getRuntime().gc();
	}

	/**
	 * Close the package WITHOUT saving its content. Reinitialize this package
	 * and cancel all changes done to it.
	 */
	public void revert() {
		revertImpl();
	}

	/**
	 * Add a thumbnail to the package. This method is provided to make easier
	 * the addition of a thumbnail in a package. You can do the same work by
	 * using the traditionnal relationship and part mechanism.
	 * 
	 * @param filename
	 *            The full path to the image file.
	 */
	public void addThumbnail(String path) throws IOException {
		// Check parameter
		if ("".equals(path))
			throw new IllegalArgumentException("path");

		// Get the filename from the path
		String filename = path
				.substring(path.lastIndexOf(File.separatorChar) + 1);

		// Create the thumbnail part name
		String contentType = ContentTypes
				.getContentTypeFromFileExtension(filename);
		PackagePartName thumbnailPartName = null;
		try {
			thumbnailPartName = PackagingURIHelper.createPartName("/docProps/"
					+ filename);
		} catch (InvalidFormatException e) {
			try {
				thumbnailPartName = PackagingURIHelper
						.createPartName("/docProps/thumbnail"
								+ path.substring(path.lastIndexOf(".") + 1));
			} catch (InvalidFormatException e2) {
				throw new InvalidOperationException(
						"Can't add a thumbnail file named '" + filename + "'");
			}
		}

		// Check if part already exist
		if (this.getPart(thumbnailPartName) != null)
			throw new InvalidOperationException(
					"You already add a thumbnail named '" + filename + "'");

		// Add the thumbnail part to this package.
		PackagePart thumbnailPart = this.createPart(thumbnailPartName,
				contentType, false);

		// Add the relationship between the package and the thumbnail part
		this.addRelationship(thumbnailPartName, TargetMode.INTERNAL,
				PackageRelationshipTypes.THUMBNAIL);

		// Copy file data to the newly created part
		StreamHelper.copyStream(new FileInputStream(path), thumbnailPart
				.getOutputStream());
	}

	/**
	 * Throws an exception if the package access mode is in read only mode
	 * (PackageAccess.Read).
	 * 
	 * @throws InvalidOperationException
	 *             Throws if a writing operation is done on a read only package.
	 * @see org.openxml4j.opc.PackageAccess
	 */
	void throwExceptionIfReadOnly() throws InvalidOperationException {
		if (packageAccess == PackageAccess.READ)
			throw new InvalidOperationException(
					"Operation not allowed, document open in read only mode!");
	}

	/**
	 * Throws an exception if the package access mode is in write only mode
	 * (PackageAccess.Write). This method is call when other methods need write
	 * right.
	 * 
	 * @throws InvalidOperationException
	 *             Throws if a read operation is done on a write only package.
	 * @see org.openxml4j.opc.PackageAccess
	 */
	void throwExceptionIfWriteOnly() throws InvalidOperationException {
		if (packageAccess == PackageAccess.WRITE)
			throw new InvalidOperationException(
					"Operation not allowed, document open in write only mode!");
	}

	/**
	 * Retrieves or creates if none exists, core package property part.
	 * 
	 * @return The PackageProperties part of this package.
	 */
	public PackageProperties getPackageProperties()
			throws InvalidFormatException {
		this.throwExceptionIfWriteOnly();
		// If no properties part has been found then we create one
		if (this.packageProperties == null) {
			this.packageProperties = new PackagePropertiesPart(this,
					PackagingURIHelper.CORE_PROPERTIES_PART_NAME);
		}
		return this.packageProperties;
	}

	/**
	 * Retrieve a part identified by its name.
	 * 
	 * @param partName
	 *            Part name of the part to retrieve.
	 * @return The part with the specified name, else <code>null</code>.
	 */
	public PackagePart getPart(PackagePartName partName) {
		throwExceptionIfWriteOnly();

		if (partName == null)
			throw new IllegalArgumentException("partName");

		// If the partlist is null, then we parse the package.
		if (partCollection == null) {
			try {
				getParts();
			} catch (InvalidFormatException e) {
				return null;
			}
		}
		return getPartImpl(partName);
	}

	/**
	 * Retrieve parts by content type.
	 * 
	 * @param contentType
	 *            The content type criteria.
	 * @return All part associated to the specified content type.
	 */
	public ArrayList<PackagePart> getPartsByContentType(String contentType) {
		ArrayList<PackagePart> retArr = new ArrayList<PackagePart>();
		for (PackagePart part : partCollection.values()) {
			if (part.getContentType().equals(contentType))
				retArr.add(part);
		}
		return retArr;
	}

	/**
	 * Retrieve parts by relationship type.
	 * 
	 * @param relationshipType
	 *            Relationship type.
	 * @return All parts which are the target of a relationship with the
	 *         specified type, if the method can't retrieve relationships from
	 *         the package, then return <code>null</code>.
	 */
	public ArrayList<PackagePart> getPartsByRelationshipType(
			String relationshipType) {
		if (relationshipType == null)
			throw new IllegalArgumentException("relationshipType");
		ArrayList<PackagePart> retArr = new ArrayList<PackagePart>();
		try {
			for (PackageRelationship rel : getRelationshipsByType(relationshipType)) {
				retArr.add(getPart(rel));
			}
		} catch (OpenXML4JException e) {
			logger
					.warn("Can't retrieve parts by relationship type: an exception has been thrown by getRelationshipsByType method");
			return null;
		}
		return retArr;
	}

	/**
	 * Get the target part from the specified relationship.
	 * 
	 * @param partRel
	 *            The part relationship uses to retrieve the part.
	 */
	public PackagePart getPart(PackageRelationship partRel) {
		PackagePart retPart = null;
		ensureRelationships();
		for (PackageRelationship rel : relationships) {
			if (rel.getRelationshipType().equals(partRel.getRelationshipType())) {
				try {
					retPart = getPart(PackagingURIHelper.createPartName(rel
							.getTargetURI()));
				} catch (InvalidFormatException e) {
					continue;
				}
				break;
			}
		}
		return retPart;
	}

	/**
	 * Load the parts of the archive if it has not been done yet The
	 * relationships of each part are not loaded
	 * 
	 * @return All this package's parts.
	 */
	public ArrayList<PackagePart> getParts() throws InvalidFormatException {
		throwExceptionIfWriteOnly();

		// If the part list is null, we parse the package to retrieve all parts.
		if (partCollection == null) {
			/* Variables use to validate OPC Compliance */

			// Ensure rule M4.1 -> A format consumer shall consider more than
			// one core properties relationship for a package to be an error
			boolean hasCorePropertiesPart = false;

			PackagePart[] parts = this.getPartsImpl();
			this.partCollection = new PackagePartCollection();
			for (PackagePart part : parts) {
				if (partCollection.containsKey(part.partName))
					throw new InvalidFormatException(
							"A part with the name '"
									+ part.partName
									+ "' already exist : Packages shall not contain equivalent part names and package implementers shall neither create nor recognize packages with equivalent part names. [M1.12]");

				// Check OPC compliance rule M4.1
				if (part.getContentType().equals(
						ContentTypes.CORE_PROPERTIES_PART)) {
					if (!hasCorePropertiesPart)
						hasCorePropertiesPart = true;
					else
						throw new InvalidFormatException(
								"OPC Compliance error [M4.1]: there is more than one core properties relationship in the package !");
				}

				PartUnmarshaller partUnmarshaller = partUnmarshallers
						.get(part.contentType);

				if (partUnmarshaller != null) {
					UnmarshallContext context = new UnmarshallContext(this,
							part.partName);
					try {
						PackagePart unmarshallPart = partUnmarshaller
								.unmarshall(context, part.getInputStream());
						partCollection.put(unmarshallPart.partName, unmarshallPart);

						// Core properties case
						if (unmarshallPart instanceof PackagePropertiesPart)
							this.packageProperties = (PackagePropertiesPart) unmarshallPart;
					} catch (IOException ioe) {
						logger.warn("Unmarshall operation : IOException for "
								+ part.partName);
						continue;
					} catch (InvalidOperationException invoe) {
						throw new InvalidFormatException(invoe.getMessage());
					}
				} else {
					try {
						partCollection.put(part.partName, part);
					} catch (InvalidOperationException e) {
						throw new InvalidFormatException(e.getMessage());
					}
				}
			}
		}
		return new ArrayList<PackagePart>(partCollection.values());
	}

	/**
	 * Create and add a part, with the specified name and content type, to the
	 * package.
	 * 
	 * @param partName
	 *            Part name.
	 * @param contentType
	 *            Part content type.
	 * @return The newly created part.
	 * @throws InvalidFormatException
	 *             If rule M1.12 is not verified : Packages shall not contain
	 *             equivalent part names and package implementers shall neither
	 *             create nor recognize packages with equivalent part names.
	 * @see {@link#createPartImpl(URI, String)}
	 */
	public PackagePart createPart(PackagePartName partName, String contentType) {
		return this.createPart(partName, contentType, true);
	}

	/**
	 * Create and add a part, with the specified name and content type, to the
	 * package. For general purpose, prefer the overload version of this method
	 * without the 'loadRelationships' parameter.
	 * 
	 * @param partName
	 *            Part name.
	 * @param contentType
	 *            Part content type.
	 * @param loadRelationships
	 *            Specify if the existing relationship part, if any, logically
	 *            associated to the newly created part will be loaded.
	 * @return The newly created part.
	 * @throws InvalidFormatException
	 *             If rule M1.12 is not verified : Packages shall not contain
	 *             equivalent part names and package implementers shall neither
	 *             create nor recognize packages with equivalent part names.
	 * @see {@link#createPartImpl(URI, String)}
	 */
	PackagePart createPart(PackagePartName partName, String contentType,
			boolean loadRelationships) {
		throwExceptionIfReadOnly();
		if (partName == null) {
			throw new IllegalArgumentException("partName");
		}

		if (contentType == null || contentType == "") {
			throw new IllegalArgumentException("contentType");
		}

		// Check if the specified part name already exists
		if (partCollection.containsKey(partName)
				&& !partCollection.get(partName).isDeleted()) {
			throw new InvalidOperationException(
					"A part with the name '"
							+ partName.getName()
							+ "' already exists : Packages shall not contain equivalent part names and package implementers shall neither create nor recognize packages with equivalent part names. [M1.12]");
		}

		/* Check OPC compliance */

		// Rule [M4.1]: The format designer shall specify and the format
		// producer
		// shall create at most one core properties relationship for a package.
		// A format consumer shall consider more than one core properties
		// relationship for a package to be an error. If present, the
		// relationship shall target the Core Properties part.
		if (contentType == ContentTypes.CORE_PROPERTIES_PART) {
			if (this.packageProperties != null)
				throw new InvalidOperationException(
						"OPC Compliance error [M4.1]: you try to add more than one core properties relationship in the package !");
		}

		/* End check OPC compliance */

		PackagePart part = this.createPartImpl(partName, contentType,
				loadRelationships);
		this.contentTypeManager.addContentType(partName, contentType);
		this.partCollection.put(partName, part);
		this.isDirty = true;
		return part;
	}

	/**
	 * Add a part to the package.
	 * 
	 * @param partName
	 *            Part name of the part to create.
	 * @param contentType
	 *            type associated with the file
	 * @param content
	 *            the contents to add. In order to have faster operation in
	 *            document merge, the data are stored in memory not on a hard
	 *            disk
	 * 
	 * @return The new part.
	 * @see {@link #createPart(PackagePart, String)}
	 */
	public PackagePart createPart(PackagePartName partName, String contentType,
			ByteArrayOutputStream content) {
		PackagePart addedPart = this.createPart(partName, contentType);
		if (addedPart == null) {
			return null;
		}
		// Extract the zip entry content to put it in the part content
		if (content != null) {
			try {
				OutputStream partOutput = addedPart.getOutputStream();
				if (partOutput == null) {
					return null;
				}

				partOutput.write(content.toByteArray(), 0, content.size());
				partOutput.close();

			} catch (IOException ioe) {
				return null;
			}
		} else {
			return null;
		}
		return addedPart;
	}

	/**
	 * Add the specified part to the package. If a part already exists in the
	 * package with the same name as the one specified, then we replace the old
	 * part by the specified part.
	 * 
	 * @param part
	 *            The part to add (or replace).
	 * @return The part added to the package, the same as the one specified.
	 * @throws InvalidFormatException
	 *             If rule M1.12 is not verified : Packages shall not contain
	 *             equivalent part names and package implementers shall neither
	 *             create nor recognize packages with equivalent part names.
	 */
	protected PackagePart addPackagePart(PackagePart part) {
		throwExceptionIfReadOnly();
		if (part == null) {
			throw new IllegalArgumentException("part");
		}

		if (partCollection.containsKey(part.partName)) {
			if (!partCollection.get(part.partName).isDeleted()) {
				throw new InvalidOperationException(
						"A part with the name '"
								+ part.partName.getName()
								+ "' already exists : Packages shall not contain equivalent part names and package implementers shall neither create nor recognize packages with equivalent part names. [M1.12]");
			} else {
				// If the specified partis flagged as deleted, we make it
				// available
				part.setDeleted(false);
				// and delete the old part to replace it thereafeter
				this.partCollection.remove(part.partName);
			}
		}
		this.partCollection.put(part.partName, part);
		this.isDirty = true;
		return part;
	}

	/**
	 * Remove the specified part in this package. If this part is relationship
	 * part, then delete all relationships in the source part.
	 * 
	 * @param part
	 *            The part to remove. If <code>null</code>, skip the action.
	 * @see #removePart(PackagePartName)
	 */
	public void removePart(PackagePart part) {
		if (part != null) {
			removePart(part.getPartName());
		}
	}

	/**
	 * Remove a part in this package. If this part is relationship part, then
	 * delete all relationships in the source part.
	 * 
	 * @param partName
	 *            The part name of the part to remove.
	 */
	public void removePart(PackagePartName partName) {
		throwExceptionIfReadOnly();
		if (partName == null || !this.containPart(partName))
			throw new IllegalArgumentException("partName");

		// Delete the specified part from the package.
		if (this.partCollection.containsKey(partName)) {
			this.partCollection.get(partName).setDeleted(true);
			this.removePartImpl(partName);
			this.partCollection.remove(partName);
		} else {
			this.removePartImpl(partName);
		}

		// Delete content type
		this.contentTypeManager.removeContentType(partName);

		// If this part is a relationship part, then delete all relationships of
		// the source part.
		if (partName.isRelationshipPartURI()) {
			URI sourceURI = PackagingURIHelper
					.getSourcePartUriFromRelationshipPartUri(partName.getURI());
			PackagePartName sourcePartName;
			try {
				sourcePartName = PackagingURIHelper.createPartName(sourceURI);
			} catch (InvalidFormatException e) {
				logger
						.error("Part name URI '"
								+ sourceURI
								+ "' is not valid ! This message is not intended to be displayed !");
				return;
			}
			if (sourcePartName.getURI().equals(
					PackagingURIHelper.PACKAGE_ROOT_URI)) {
				clearRelationships();
			} else if (containPart(sourcePartName)) {
				PackagePart part = getPart(sourcePartName);
				if (part != null)
					part.clearRelationships();
			}
		}

		this.isDirty = true;
	}

	/**
	 * Remove a part from this package as well as its relationship part, if one
	 * exists, and all parts listed in the relationship part. Be aware that this
	 * do not delete relationships which target the specified part.
	 * 
	 * @param partName
	 *            The name of the part to delete.
	 * @throws InvalidFormatException
	 *             Throws if the associated relationship part of the specified
	 *             part is not valid.
	 */
	public void removePartRecursive(PackagePartName partName)
			throws InvalidFormatException {
		// Retrieves relationship part, if one exists
		PackagePart relPart = this.partCollection.get(PackagingURIHelper
				.getRelationshipPartName(partName));
		// Retrieves PackagePart object from the package
		PackagePart partToRemove = this.partCollection.get(partName);

		if (relPart != null) {
			PackageRelationshipCollection partRels = new PackageRelationshipCollection(
					partToRemove);
			for (PackageRelationship rel : partRels) {
				PackagePartName partNameToRemove = PackagingURIHelper
						.createPartName(PackagingURIHelper.resolvePartUri(rel
								.getSourceURI(), rel.getTargetURI()));
				removePart(partNameToRemove);
			}

			// Finally delete its relationship part if one exists
			this.removePart(relPart.partName);
		}

		// Delete the specified part
		this.removePart(partToRemove.partName);
	}

	/**
	 * Delete the part with the specified name and its associated relationships
	 * part if one exists. Prefer the use of this method to delete a part in the
	 * package, compare to the remove() methods that don't remove associated
	 * relationships part.
	 * 
	 * @param partName
	 *            Name of the part to delete
	 */
	public void deletePart(PackagePartName partName) {
		if (partName == null)
			throw new IllegalArgumentException("partName");

		// Remove the part
		this.removePart(partName);
		// Remove the relationships part
		this.removePart(PackagingURIHelper.getRelationshipPartName(partName));
	}

	/**
	 * Delete the part with the specified name and all part listed in its
	 * associated relationships part if one exists. This process is recursively
	 * apply to all parts in the relationships part of the specified part.
	 * Prefer the use of this method to delete a part in the package, compare to
	 * the remove() methods that don't remove associated relationships part.
	 * 
	 * @param partName
	 *            Name of the part to delete
	 */
	public void deletePartRecursive(PackagePartName partName) {
		if (partName == null || !this.containPart(partName))
			throw new IllegalArgumentException("partName");

		PackagePart partToDelete = this.getPart(partName);
		// Remove the part
		this.removePart(partName);
		// Remove all relationship parts associated
		try {
			for (PackageRelationship relationship : partToDelete
					.getRelationships()) {
				PackagePartName targetPartName = PackagingURIHelper
						.createPartName(PackagingURIHelper.resolvePartUri(
								partName.getURI(), relationship.getTargetURI()));
				this.deletePartRecursive(targetPartName);
			}
		} catch (InvalidFormatException e) {
			logger.warn("An exception occurs while deleting part '"
					+ partName.getName()
					+ "'. Some parts may remain in the package. - "
					+ e.getMessage());
			return;
		}
		// Remove the relationships part
		PackagePartName relationshipPartName = PackagingURIHelper
				.getRelationshipPartName(partName);
		if (relationshipPartName != null && containPart(relationshipPartName))
			this.removePart(relationshipPartName);
	}

	/**
	 * Check if a part already exists in this package from its name.
	 * 
	 * @param partName
	 *            Part name to check.
	 * @return <i>true</i> if the part is logically added to this package, else
	 *         <i>false</i>.
	 */
	public boolean containPart(PackagePartName partName) {
		return (this.getPart(partName) != null);
	}

	/**
	 * Add a relationship to the package (except relationships part).
	 * 
	 * Check rule M4.1 : The format designer shall specify and the format
	 * producer shall create at most one core properties relationship for a
	 * package. A format consumer shall consider more than one core properties
	 * relationship for a package to be an error. If present, the relationship
	 * shall target the Core Properties part.
	 * 
	 * Check rule M1.25: The Relationships part shall not have relationships to
	 * any other part. Package implementers shall enforce this requirement upon
	 * the attempt to create such a relationship and shall treat any such
	 * relationship as invalid.
	 * 
	 * @param targetPartName
	 *            Target part name.
	 * @param targetMode
	 *            Target mode, either Internal or External.
	 * @param relationshipType
	 *            Relationship type.
	 * @param relID
	 *            ID of the relationship.
	 * @see PackageRelationshipTypes
	 */
	public PackageRelationship addRelationship(PackagePartName targetPartName,
			TargetMode targetMode, String relationshipType, String relID) {
		/* Check OPC compliance */

		// Check rule M4.1 : The format designer shall specify and the format
		// producer
		// shall create at most one core properties relationship for a package.
		// A format consumer shall consider more than one core properties
		// relationship for a package to be an error. If present, the
		// relationship shall target the Core Properties part.
		if (relationshipType.equals(PackageRelationshipTypes.CORE_PROPERTIES)
				&& this.packageProperties != null)
			throw new InvalidOperationException(
					"OPC Compliance error [M4.1]: can't add another core properties part ! Use the built-in package method instead.");

		/*
		 * Check rule M1.25: The Relationships part shall not have relationships
		 * to any other part. Package implementers shall enforce this
		 * requirement upon the attempt to create such a relationship and shall
		 * treat any such relationship as invalid.
		 */
		if (targetPartName.isRelationshipPartURI()) {
			throw new InvalidOperationException(
					"Rule M1.25: The Relationships part shall not have relationships to any other part.");
		}

		/* End OPC compliance */

		ensureRelationships();
		PackageRelationship retRel = relationships.addRelationship(
				targetPartName.getURI(), targetMode, relationshipType, relID);
		this.isDirty = true;
		return retRel;
	}

	/**
	 * Add a package relationship.
	 * 
	 * @param targetPartName
	 *            Target part name.
	 * @param targetMode
	 *            Target mode, either Internal or External.
	 * @param relationshipType
	 *            Relationship type.
	 * @see PackageRelationshipTypes
	 */
	public PackageRelationship addRelationship(PackagePartName targetPartName,
			TargetMode targetMode, String relationshipType) {
		return this.addRelationship(targetPartName, targetMode,
				relationshipType, null);
	}

	/**
	 * Adds an external relationship to a part (except relationships part).
	 * 
	 * The targets of external relationships are not subject to the same
	 * validity checks that internal ones are, as the contents is potentially
	 * any file, URL or similar.
	 * 
	 * @param target
	 *            External target of the relationship
	 * @param relationshipType
	 *            Type of relationship.
	 * @return The newly created and added relationship
	 * @see org.openxml4j.opc.RelationshipSource#addExternalRelationship(java.lang.String,
	 *      java.lang.String)
	 */
	public PackageRelationship addExternalRelationship(String target,
			String relationshipType) {
		return addExternalRelationship(target, relationshipType, null);
	}

	/**
	 * Adds an external relationship to a part (except relationships part).
	 * 
	 * The targets of external relationships are not subject to the same
	 * validity checks that internal ones are, as the contents is potentially
	 * any file, URL or similar.
	 * 
	 * @param target
	 *            External target of the relationship
	 * @param relationshipType
	 *            Type of relationship.
	 * @param id
	 *            Relationship unique id.
	 * @return The newly created and added relationship
	 * @see org.openxml4j.opc.RelationshipSource#addExternalRelationship(java.lang.String,
	 *      java.lang.String)
	 */
	public PackageRelationship addExternalRelationship(String target,
			String relationshipType, String id) {
		if (target == null) {
			throw new IllegalArgumentException("target");
		}
		if (relationshipType == null) {
			throw new IllegalArgumentException("relationshipType");
		}

		URI targetURI;
		try {
			targetURI = new URI(target);
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("Invalid target - " + e);
		}

		ensureRelationships();
		PackageRelationship retRel = relationships.addRelationship(targetURI,
				TargetMode.EXTERNAL, relationshipType, id);
		this.isDirty = true;
		return retRel;
	}

	/**
	 * Delete a relationship from this package.
	 * 
	 * @param id
	 *            Id of the relationship to delete.
	 */
	public void removeRelationship(String id) {
		if (relationships != null) {
			relationships.removeRelationship(id);
			this.isDirty = true;
		}
	}

	/**
	 * Retrieves all package relationships.
	 * 
	 * @return All package relationships of this package.
	 * @throws OpenXML4JException
	 * @see {@link #getRelationshipsHelper(String)}
	 */
	public PackageRelationshipCollection getRelationships()
			throws OpenXML4JException {
		return getRelationshipsHelper(null);
	}

	/**
	 * Retrives all relationships with the specified type.
	 * 
	 * @param relationshipType
	 *            The filter specifying the relationship type.
	 * @return All relationships with the specified relationship type.
	 * @throws OpenXML4JException
	 */
	public PackageRelationshipCollection getRelationshipsByType(
			String relationshipType) throws IllegalArgumentException,
			OpenXML4JException {
		throwExceptionIfWriteOnly();
		if (relationshipType == null) {
			throw new IllegalArgumentException("relationshipType");
		}
		return getRelationshipsHelper(relationshipType);
	}

	/**
	 * Retrieves all relationships with specified id (normally just ine because
	 * a relationship id is supposed to be unique).
	 * 
	 * @param id
	 *            Id of the wanted relationship.
	 * @throws OpenXML4JException
	 */
	private PackageRelationshipCollection getRelationshipsHelper(String id)
			throws OpenXML4JException {
		throwExceptionIfWriteOnly();
		ensureRelationships();
		return this.relationships.getRelationships(id);
	}

	/**
	 * Clear package relationships.
	 */
	public void clearRelationships() {
		if (relationships != null) {
			relationships.clear();
			this.isDirty = true;
		}
	}

	/**
	 * Ensure that the relationships collection is not null.
	 */
	public void ensureRelationships() {
		if (this.relationships == null) {
			try {
				this.relationships = new PackageRelationshipCollection(this);
			} catch (InvalidFormatException e) {
				this.relationships = new PackageRelationshipCollection();
			}
		}
	}

	/**
	 * @see org.openxml4j.opc.RelationshipSource#getRelationship(java.lang.String)
	 */
	public PackageRelationship getRelationship(String id) {
		return this.relationships.getRelationshipByID(id);
	}

	/**
	 * @see org.openxml4j.opc.RelationshipSource#hasRelationships()
	 */
	public boolean hasRelationships() {
		return (relationships.size() > 0);
	}

	/**
	 * @see org.openxml4j.opc.RelationshipSource#isRelationshipExists(org.openxml4j.opc.PackageRelationship)
	 */
	@SuppressWarnings("finally")
	public boolean isRelationshipExists(PackageRelationship rel) {
		try {
			for (PackageRelationship r : this.getRelationships()) {
				if (r == rel)
					return true;
			}
		} finally {
			return false;
		}
	}

	/**
	 * Add a marshaller.
	 * 
	 * @param contentType
	 *            The content type to bind to the specified marshaller.
	 * @param marshaller
	 *            The marshaller to register with the specified content type.
	 */
	public void addMarshaller(String contentType, PartMarshaller marshaller) {
		try {
			partMarshallers.put(new ContentType(contentType), marshaller);
		} catch (InvalidFormatException e) {
			logger.warn("The specified content type is not valid: '"
					+ e.getMessage() + "'. The marshaller will not be added !");
		}
	}

	/**
	 * Add an unmarshaller.
	 * 
	 * @param contentType
	 *            The content type to bind to the specified unmarshaller.
	 * @param unmarshaller
	 *            The unmarshaller to register with the specified content type.
	 */
	public void addUnmarshaller(String contentType,
			PartUnmarshaller unmarshaller) {
		try {
			partUnmarshallers.put(new ContentType(contentType), unmarshaller);
		} catch (InvalidFormatException e) {
			logger.warn("The specified content type is not valid: '"
					+ e.getMessage()
					+ "'. The unmarshaller will not be added !");
		}
	}

	/**
	 * Remove a marshaller by its content type.
	 * 
	 * @param contentType
	 *            The content type associated with the marshaller to remove.
	 */
	public void removeMarshaller(String contentType) {
		partMarshallers.remove(contentType);
	}

	/**
	 * Remove an unmarshaller by its content type.
	 * 
	 * @param contentType
	 *            The content type associated with the unmarshaller to remove.
	 */
	public void removeUnmarshaller(String contentType) {
		partUnmarshallers.remove(contentType);
	}

	/* Accesseurs */

	/**
	 * Get the package access mode.
	 * 
	 * @return the packageAccess The current package access.
	 */
	public PackageAccess getPackageAccess() {
		return packageAccess;
	}

	/**
	 * Validates the package compliance with the OPC specifications.
	 * 
	 * @return <b>true</b> if the package is valid else <b>false</b>
	 */
	public boolean validatePackage(Package pkg) throws InvalidFormatException {
		throw new InvalidOperationException("Not implemented yet !!!");
	}

	/**
	 * Save the document in the specified file.
	 * 
	 * @param targetFile
	 *            Destination file.
	 * @throws IOException
	 *             Throws if an IO exception occur.
	 * @see #save(OutputStream)
	 */
	public void save(File targetFile) throws IOException {
		if (targetFile == null)
			throw new IllegalArgumentException("targetFile");

		this.throwExceptionIfReadOnly();
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(targetFile);
		} catch (FileNotFoundException e) {
			throw new IOException(e.getLocalizedMessage());
		}
		this.save(fos);
	}

	/**
	 * Save the document in the specified output stream.
	 * 
	 * @param stream
	 *            The stream to save the package.
	 * @see #saveImpl(OutputStream)
	 */
	public void save(OutputStream outputStream) throws IOException {
		throwExceptionIfReadOnly();
		this.saveImpl(outputStream);
	}

	/**
	 * Core method to create a package part. This method must be implemented by
	 * the subclass.
	 * 
	 * @param partName
	 *            URI of the part to create.
	 * @param contentType
	 *            Content type of the part to create.
	 * @return The newly created package part.
	 */
	protected abstract PackagePart createPartImpl(PackagePartName partName,
			String contentType, boolean loadRelationships);

	/**
	 * Core method to delete a package part. This method must be implemented by
	 * the subclass.
	 * 
	 * @param partName
	 *            The URI of the part to delete.
	 */
	protected abstract void removePartImpl(PackagePartName partName);

	/**
	 * Flush the package but not save.
	 */
	protected abstract void flushImpl();

	/**
	 * Close the package and cause a save of the package.
	 * 
	 */
	protected abstract void closeImpl() throws IOException;

	/**
	 * Close the package without saving the document. Discard all changes made
	 * to this package.
	 */
	protected abstract void revertImpl();

	/**
	 * Save the package into the specified output stream.
	 * 
	 * @param outputStream
	 *            The output stream use to save this package.
	 */
	protected abstract void saveImpl(OutputStream outputStream)
			throws IOException;

	/**
	 * Get the package part mapped to the specified URI.
	 * 
	 * @param partName
	 *            The URI of the part to retrieve.
	 * @return The package part located by the specified URI, else <b>null</b>.
	 */
	protected abstract PackagePart getPartImpl(PackagePartName partName);

	/**
	 * Get all parts link to the package.
	 * 
	 * @return A list of the part owned by the package.
	 */
	protected abstract PackagePart[] getPartsImpl()
			throws InvalidFormatException;
}
