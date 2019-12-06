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
 * 
 * - OR -
 * 
 * ====================================================================
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
 */

package org.openxml4j.opc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;

import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.exceptions.InvalidOperationException;
import org.openxml4j.exceptions.OpenXML4JException;
import org.openxml4j.opc.internal.ContentType;

/**
 * Provides a base class for parts stored in a Package.
 * 
 * @author Julien Chable
 * @version 0.9
 */
public abstract class PackagePart implements RelationshipSource {

	/**
	 * This part's container.
	 */
	protected Package container;

	/**
	 * The part name. (required by the specification [M1.1])
	 */
	protected PackagePartName partName;

	/**
	 * The type of content of this part. (required by the specification [M1.2])
	 */
	protected ContentType contentType;

	/**
	 * Flag to know if this part is a relationship.
	 */
	private boolean isRelationshipPart;

	/**
	 * Flag to know if this part has been logically deleted.
	 */
	private boolean isDeleted;

	/**
	 * This part's relationships.
	 */
	private PackageRelationshipCollection relationships;

	/**
	 * Constructor.
	 * 
	 * @param pack
	 *            Parent package.
	 * @param partName
	 *            The part name, relative to the parent Package root.
	 * @param contentType
	 *            The content type.
	 * @throws InvalidFormatException
	 *             If the specified URI is not valid.
	 */
	protected PackagePart(Package pack, PackagePartName partName,
			ContentType contentType) throws InvalidFormatException {
		this(pack, partName, contentType, true);
	}

	/**
	 * Constructor.
	 * 
	 * @param pack
	 *            Parent package.
	 * @param partName
	 *            The part name, relative to the parent Package root.
	 * @param contentType
	 *            The content type.
	 * @param loadRelationships
	 *            Specify if the relationships will be loaded
	 * @throws InvalidFormatException
	 *             If the specified URI is not valid.
	 */
	protected PackagePart(Package pack, PackagePartName partName,
			ContentType contentType, boolean loadRelationships)
			throws InvalidFormatException {
		this.partName = partName;
		this.contentType = contentType;
		this.container = (ZipPackage) pack;

		// Check if this part is a relationship part
		isRelationshipPart = this.partName.isRelationshipPartURI();

		// Load relationships if any
		if (loadRelationships)
			loadRelationships();
	}

	/**
	 * Constructor.
	 * 
	 * @param pack
	 *            Parent package.
	 * @param partName
	 *            The part name, relative to the parent Package root.
	 * @param contentType
	 *            The Multipurpose Internet Mail Extensions (MIME) content type
	 *            of the part's data stream.
	 */
	public PackagePart(Package pack, PackagePartName partName,
			String contentType) throws InvalidFormatException {
		this(pack, partName, new ContentType(contentType));
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

		if (relationships == null) {
			relationships = new PackageRelationshipCollection();
		}

		URI targetURI;
		try {
			targetURI = new URI(target);
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("Invalid target - " + e);
		}

		return relationships.addRelationship(targetURI, TargetMode.EXTERNAL,
				relationshipType, id);
	}

	/**
	 * Add a relationship to a part (except relationships part).
	 * 
	 * @param targetPartName
	 *            Name of the target part. This one must be relative to the
	 *            source root directory of the part.
	 * @param targetMode
	 *            Mode [Internal|External].
	 * @param relationshipType
	 *            Type of relationship.
	 * @return The newly created and added relationship
	 * @see org.openxml4j.opc.RelationshipSource#addRelationship(org.openxml4j.opc.PackagePartName,
	 *      org.openxml4j.opc.TargetMode, java.lang.String)
	 */
	public PackageRelationship addRelationship(PackagePartName targetPartName,
			TargetMode targetMode, String relationshipType) {
		return addRelationship(targetPartName, targetMode, relationshipType,
				null);
	}

	/**
	 * Add a relationship to a part (except relationships part).
	 * 
	 * Check rule M1.25: The Relationships part shall not have relationships to
	 * any other part. Package implementers shall enforce this requirement upon
	 * the attempt to create such a relationship and shall treat any such
	 * relationship as invalid.
	 * 
	 * @param targetPartName
	 *            Name of the target part. This one must be relative to the
	 *            source root directory of the part.
	 * @param targetMode
	 *            Mode [Internal|External].
	 * @param relationshipType
	 *            Type of relationship.
	 * @param id
	 *            Relationship unique id.
	 * @return The newly created and added relationship
	 * 
	 * @throws InvalidFormatException
	 *             If the URI point to a relationship part URI.
	 * @see org.openxml4j.opc.RelationshipSource#addRelationship(org.openxml4j.opc.PackagePartName,
	 *      org.openxml4j.opc.TargetMode, java.lang.String, java.lang.String)
	 */
	public PackageRelationship addRelationship(PackagePartName targetPartName,
			TargetMode targetMode, String relationshipType, String id) {
		container.throwExceptionIfReadOnly();

		if (targetPartName == null) {
			throw new IllegalArgumentException("targetPartName");
		}
		if (targetMode == null) {
			throw new IllegalArgumentException("targetMode");
		}
		if (relationshipType == null) {
			throw new IllegalArgumentException("relationshipType");
		}

		if (this.isRelationshipPart || targetPartName.isRelationshipPartURI()) {
			throw new InvalidOperationException(
					"Rule M1.25: The Relationships part shall not have relationships to any other part.");
		}
		
		if (relationships == null) {
			relationships = new PackageRelationshipCollection();
		}

		return relationships.addRelationship(targetPartName.getURI(),
				targetMode, relationshipType, id);
	}

	/**
	 * Add a relationship to a part (except relationships part).
	 * 
	 * @param targetURI
	 *            URI the target part. Must be relative to the source root
	 *            directory of the part.
	 * @param targetMode
	 *            Mode [Internal|External].
	 * @param relationshipType
	 *            Type of relationship.
	 * @return The newly created and added relationship
	 * @see org.openxml4j.opc.RelationshipSource#addRelationship(org.openxml4j.opc.PackagePartName,
	 *      org.openxml4j.opc.TargetMode, java.lang.String)
	 */
	public PackageRelationship addRelationship(URI targetURI,
			TargetMode targetMode, String relationshipType) {
		return addRelationship(targetURI, targetMode, relationshipType, null);
	}

	/**
	 * Add a relationship to a part (except relationships part).
	 * 
	 * Check rule M1.25: The Relationships part shall not have relationships to
	 * any other part. Package implementers shall enforce this requirement upon
	 * the attempt to create such a relationship and shall treat any such
	 * relationship as invalid.
	 * 
	 * @param targetURI
	 *            URI of the target part. Must be relative to the source root
	 *            directory of the part.
	 * @param targetMode
	 *            Mode [Internal|External].
	 * @param relationshipType
	 *            Type of relationship.
	 * @param id
	 *            Relationship unique id.
	 * @return The newly created and added relationship
	 * 
	 * @throws InvalidFormatException
	 *             If the URI point to a relationship part URI.
	 * @see org.openxml4j.opc.RelationshipSource#addRelationship(org.openxml4j.opc.PackagePartName,
	 *      org.openxml4j.opc.TargetMode, java.lang.String, java.lang.String)
	 */
	public PackageRelationship addRelationship(URI targetURI,
			TargetMode targetMode, String relationshipType, String id) {
		container.throwExceptionIfReadOnly();

		if (targetURI == null) {
			throw new IllegalArgumentException("targetPartName");
		}
		if (targetMode == null) {
			throw new IllegalArgumentException("targetMode");
		}
		if (relationshipType == null) {
			throw new IllegalArgumentException("relationshipType");
		}

		// Try to retrieve the target part

		if (this.isRelationshipPart
				|| PackagingURIHelper.isRelationshipPartURI(targetURI)) {
			throw new InvalidOperationException(
					"Rule M1.25: The Relationships part shall not have relationships to any other part.");
		}

		if (relationships == null) {
			relationships = new PackageRelationshipCollection();
		}

		return relationships.addRelationship(targetURI,
				targetMode, relationshipType, id);
	}

	/**
	 * @see org.openxml4j.opc.RelationshipSource#clearRelationships()
	 */
	public void clearRelationships() {
		if (relationships != null) {
			relationships.clear();
		}
	}

	/**
	 * Delete the relationship specified by its id.
	 * 
	 * @param id
	 *            The ID identified the part to delete.
	 * @see org.openxml4j.opc.RelationshipSource#removeRelationship(java.lang.String)
	 */
	public void removeRelationship(String id) {
		this.container.throwExceptionIfReadOnly();
		if (this.relationships != null)
			this.relationships.removeRelationship(id);
	}

	/**
	 * Retrieve all the relationships attached to this part.
	 * 
	 * @return This part's relationships.
	 * @throws OpenXML4JException
	 * @see org.openxml4j.opc.RelationshipSource#getRelationships()
	 */
	public PackageRelationshipCollection getRelationships()
			throws InvalidFormatException {
		return getRelationshipsCore(null);
	}

	/**
	 * Retrieves a package relationship from its id.
	 * 
	 * @param id
	 *            ID of the package relationship to retrieve.
	 * @return The package relationship
	 * @see org.openxml4j.opc.RelationshipSource#getRelationship(java.lang.String)
	 */
	public PackageRelationship getRelationship(String id) {
		return this.relationships.getRelationshipByID(id);
	}

	/**
	 * Retrieve all relationships attached to this part which have the specified
	 * type.
	 * 
	 * @param relationshipType
	 *            Relationship type filter.
	 * @return All relationships from this part that have the specified type.
	 * @throws InvalidFormatException
	 *             If an error occurs while parsing the part.
	 * @throws InvalidOperationException
	 *             If the package is open in write only mode.
	 * @see org.openxml4j.opc.RelationshipSource#getRelationshipsByType(java.lang.String)
	 */
	public PackageRelationshipCollection getRelationshipsByType(
			String relationshipType) throws InvalidFormatException {
		container.throwExceptionIfWriteOnly();

		return getRelationshipsCore(relationshipType);
	}

	/**
	 * Implementation of the getRelationships method().
	 * 
	 * @param filter
	 *            Relationship type filter. If <i>null</i> then the filter is
	 *            disabled and return all the relationships.
	 * @return All relationships from this part that have the specified type.
	 * @throws InvalidFormatException
	 *             Throws if an error occurs during parsing the relationships
	 *             part.
	 * @throws InvalidOperationException
	 *             Throws if the package is open en write only mode.
	 * @see org.openxml4j.opc.PackagePart.getRelationshipsByType()
	 */
	private PackageRelationshipCollection getRelationshipsCore(String filter)
			throws InvalidFormatException {
		this.container.throwExceptionIfWriteOnly();
		if (relationships == null) {
			this.throwExceptionIfRelationship();
			relationships = new PackageRelationshipCollection(this);
		}
		return new PackageRelationshipCollection(relationships, filter);
	}

	/**
	 * Knows if the part have any relationships.
	 * 
	 * @return <b>true</b> if the part have at least one relationship else
	 *         <b>false</b>.
	 * @see org.openxml4j.opc.RelationshipSource#hasRelationships()
	 */
	public boolean hasRelationships() {
		return (!this.isRelationshipPart && (relationships != null && relationships
				.size() > 0));
	}

	/**
	 * Checks if the specified relationship is part of this package part.
	 * 
	 * @param rel
	 *            The relationship to check.
	 * @return <b>true</b> if the specified relationship exists in this part,
	 *         else returns <b>false</b>
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
	 * Get the input stream of this part to read its content.
	 * 
	 * @return The input stream of the content of this part, else
	 *         <code>null</code>.
	 */
	public InputStream getInputStream() throws IOException {
		InputStream inStream = this.getInputStreamImpl();
		if (inStream == null) {
			throw new IOException("Can't obtain the input stream from "
					+ partName.getName());
		} else
			return inStream;
	}

	/**
	 * Get the output stream of this part. If the part is originally embedded in
	 * Zip package, it'll be transform intot a <i>MemoryPackagePart</i> in
	 * order to write inside (the standard Java API doesn't allow to write in
	 * the file)
	 * 
	 * @see org.openxml4j.opc.internal.MemoryPackagePart
	 */
	public OutputStream getOutputStream() {
		OutputStream outStream;
		// If this part is a zip package part (read only by design) we convert
		// this part into a MemoryPackagePart instance for write purpose.
		if (this instanceof ZipPackagePart) {
			// Delete logically this part
			this.container.removePart(this.partName);

			// Create a memory part
			PackagePart part = container.createPart(this.partName,
					this.contentType.toString(), false);
			part.relationships = this.relationships;
			if (part == null) {
				throw new InvalidOperationException(
						"Can't create a temporary part !");
			}
			outStream = part.getOutputStreamImpl();
		} else {
			outStream = this.getOutputStreamImpl();
		}
		return outStream;
	}

	/**
	 * Throws an exception if this package part is a relationship part.
	 * 
	 * @throws InvalidOperationException
	 *             If this part is a relationship part.
	 */
	private void throwExceptionIfRelationship()
			throws InvalidOperationException {
		if (this.isRelationshipPart)
			throw new InvalidOperationException(
					"Can do this operation on a relationship part !");
	}

	/**
	 * Ensure the package relationships collection instance is built.
	 * 
	 * @throws InvalidFormatException
	 *             Throws if
	 */
	private void loadRelationships() throws InvalidFormatException {
		if (this.relationships == null && !this.isRelationshipPart) {
			this.throwExceptionIfRelationship();
			relationships = new PackageRelationshipCollection(this);
		}
	}

	/*
	 * Accessors
	 */

	/**
	 * @return the uri
	 */
	public PackagePartName getPartName() {
		return partName;
	}

	/**
	 * @return the contentType
	 */
	public String getContentType() {
		return contentType.toString();
	}

	/**
	 * Set the content type.
	 * 
	 * @param contentType
	 *            the contentType to set
	 * 
	 * @throws InvalidFormatException
	 *             Throws if the content type is not valid.
	 * @throws InvalidOperationException
	 *             Throws if you try to change the content type whereas this
	 *             part is already attached to a package.
	 */
	public void setContentType(String contentType)
			throws InvalidFormatException {
		if (container == null)
			this.contentType = new ContentType(contentType);
		else
			throw new InvalidOperationException(
					"You can't change the content type of a part.");
	}

	public Package getPackage() {
		return container;
	}

	/**
	 * @return
	 */
	public boolean isRelationshipPart() {
		return this.isRelationshipPart;
	}

	/**
	 * @return
	 */
	public boolean isDeleted() {
		return isDeleted;
	}

	/**
	 * @param isDeleted
	 *            the isDeleted to set
	 */
	public void setDeleted(boolean isDeleted) {
		this.isDeleted = isDeleted;
	}

	@Override
	public String toString() {
		return "Name: " + this.partName + " - Content Type: "
				+ this.contentType.toString();
	}

	/*-------------- Abstract methods ------------- */

	/**
	 * Abtract method that get the input stream of this part.
	 * 
	 * @exception IOException
	 *                Throws if an IO Exception occur in the implementation
	 *                method.
	 */
	protected abstract InputStream getInputStreamImpl() throws IOException;

	/**
	 * Abstract method that get the output stream of this part.
	 */
	protected abstract OutputStream getOutputStreamImpl();

	/**
	 * Save the content of this part and the associated relationships part (if
	 * this part own at least one relationship) into the specified output
	 * stream.
	 * 
	 * @param zos
	 *            Output stream to save this part.
	 * @throws OpenXML4JException
	 *             If any exception occur.
	 */
	public abstract boolean save(OutputStream zos) throws OpenXML4JException;

	/**
	 * Load the content of this part.
	 * 
	 * @param ios
	 *            The input stream of the content to load.
	 * @return <b>true</b> if the content has been successfully loaded, else
	 *         <b>false</b>.
	 * @throws InvalidFormatException
	 *             Throws if the content format is invalid.
	 */
	public abstract boolean load(InputStream ios) throws InvalidFormatException;

	/**
	 * Close this part : flush this part, close the input stream and output
	 * stream. After this method call, the part must be available for packaging.
	 */
	public abstract void close();

	/**
	 * Flush the content of this part. If the input stream and/or output stream
	 * as in a waiting state to read or write, the must to empty their
	 * respective buffer.
	 */
	public abstract void flush();
}
