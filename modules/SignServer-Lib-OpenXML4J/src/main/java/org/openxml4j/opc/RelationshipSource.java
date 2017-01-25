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

import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.exceptions.InvalidOperationException;
import org.openxml4j.exceptions.OpenXML4JException;

public interface RelationshipSource {

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
	 */
	public abstract PackageRelationship addRelationship(
			PackagePartName targetPartName, TargetMode targetMode,
			String relationshipType);

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
	 */
	public abstract PackageRelationship addRelationship(
			PackagePartName targetPartName, TargetMode targetMode,
			String relationshipType, String id);

	/**
	 * Adds an external relationship to a part
	 *  (except relationships part).
	 * 
	 * The targets of external relationships are not
	 *  subject to the same validity checks that internal
	 *  ones are, as the contents is potentially
	 *  any file, URL or similar.
	 *  
	 * @param target External target of the relationship
	 * @param relationshipType Type of relationship.
	 * @return The newly created and added relationship
	 * @see org.openxml4j.opc.RelationshipSource#addExternalRelationship(java.lang.String, java.lang.String)
	 */
	public PackageRelationship addExternalRelationship(String target, String relationshipType);
	
	/**
	 * Adds an external relationship to a part
	 *  (except relationships part).
	 * 
	 * The targets of external relationships are not
	 *  subject to the same validity checks that internal
	 *  ones are, as the contents is potentially
	 *  any file, URL or similar.
	 *  
	 * @param target External target of the relationship
	 * @param relationshipType Type of relationship.
	 * @param id Relationship unique id.
	 * @return The newly created and added relationship
	 * @see org.openxml4j.opc.RelationshipSource#addExternalRelationship(java.lang.String, java.lang.String)
	 */
	public PackageRelationship addExternalRelationship(String target, String relationshipType, String id);
	
	/**
	 * Delete all the relationships attached to this.
	 */
	public abstract void clearRelationships();

	/**
	 * Delete the relationship specified by its id.
	 * 
	 * @param id
	 *            The ID identified the part to delete.
	 */
	public abstract void removeRelationship(String id);

	/**
	 * Retrieve all the relationships attached to this.
	 * 
	 * @return This part's relationships.
	 * @throws OpenXML4JException
	 */
	public abstract PackageRelationshipCollection getRelationships()
			throws InvalidFormatException, OpenXML4JException;

	/**
	 * Retrieves a package relationship from its id.
	 * 
	 * @param id
	 *            ID of the package relationship to retrieve.
	 * @return The package relationship
	 */
	public abstract PackageRelationship getRelationship(String id);

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
	 */
	public abstract PackageRelationshipCollection getRelationshipsByType(
			String relationshipType) throws InvalidFormatException, 
			IllegalArgumentException, OpenXML4JException;

	/**
	 * Knows if the part have any relationships.
	 * 
	 * @return <b>true</b> if the part have at least one relationship else
	 *         <b>false</b>.
	 */
	public abstract boolean hasRelationships();

	/**
	 * Checks if the specified relationship is part of this package part.
	 * 
	 * @param rel
	 *            The relationship to check.
	 * @return <b>true</b> if the specified relationship exists in this part,
	 *         else returns <b>false</b>
	 */
	@SuppressWarnings("finally")
	public abstract boolean isRelationshipExists(PackageRelationship rel);

}
