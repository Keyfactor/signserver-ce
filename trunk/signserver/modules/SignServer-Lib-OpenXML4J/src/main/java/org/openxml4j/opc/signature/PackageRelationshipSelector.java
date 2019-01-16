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

package org.openxml4j.opc.signature;

import java.net.URI;
import java.util.List;
import java.util.Vector;

import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.exceptions.OpenXML4JException;
import org.openxml4j.opc.PackagePartName;

/**
 * 
 * Defines PackageRelationship criteria to select part-level or package-level
 * relationships.
 * 
 * @author aziz.goktepe (aka rayback_2)
 * 
 * patch originally created for SignServer project {@link http://www.signserver.org}
 * 
 */
public class PackageRelationshipSelector {
	protected URI sourceURI;
	protected PackagePartName relationshipPartName;
	protected List<RelationshipIdentifier> relationshipIdentifiers;
	protected boolean isAllRelationshipsIncluded;

	public URI getSourceURI() {
		return sourceURI;
	}

	/**
	 * indication whether all relationships in a relationship part are included
	 * . If true , means every relationship in relationship part is included.
	 * (that is no relationship transform applied) If false, means some subset
	 * of relationships is included (that is there's relationship transform
	 * applied)
	 * 
	 * NOTE : if true getRelationshipIdentifiers() will return null!
	 * 
	 * @return
	 */
	public boolean getIsAllRelationshipsIncluded() {
		return isAllRelationshipsIncluded;
	}

	/**
	 * gets the package part name of the current relationship part
	 */
	public PackagePartName getRelationshipPartName()
			throws InvalidFormatException {

		return relationshipPartName;
	}

	/**
	 * get all relationship identifiers included in signature (that is
	 * parameters to relationship transform)
	 * 
	 * @return NULL if and only if all relationships are included and
	 *         getIsAllRelationshipsIncluded() returns true
	 */
	public List<RelationshipIdentifier> getRelationshipIdentifiers() {
		if (isAllRelationshipsIncluded)
			return null;
		else
			return relationshipIdentifiers;
	}

	public void addRelationshipIdentifier(
			RelationshipIdentifier pRelationshipIdentifier)
			throws OpenXML4JException {
		// can't add identifier if all relationships are included already
		if (isAllRelationshipsIncluded) {
			throw new OpenXML4JException(
					"All relationships for relationship part : "
							+ this.relationshipPartName.toString()
							+ " are set to be included. Cannot add relationship identifier");
		}

		for (RelationshipIdentifier tempRelId : relationshipIdentifiers) {
			if (tempRelId.selectionCriteria
					.equals(pRelationshipIdentifier.selectionCriteria)
					&& tempRelId.selectorType
							.equals(pRelationshipIdentifier.selectorType))
				throw new OpenXML4JException(
						"Relationship Identifier already added. Relationship Identifier to add: "
								+ pRelationshipIdentifier);
		}
		relationshipIdentifiers.add(pRelationshipIdentifier);
	}

	public RelationshipIdentifier addRelationshipIdentifier(
			PackageRelationshipSelectorType pSelectorType,
			String pSelectionCriteria) throws Exception {
		RelationshipIdentifier relIdentifier = new RelationshipIdentifier(
				pSelectorType, pSelectionCriteria);
		addRelationshipIdentifier(relIdentifier);
		return relIdentifier;
	}

	public PackageRelationshipSelector(URI pSourceURI,
			PackagePartName pRelationshipPartName) {

		this(pSourceURI, pRelationshipPartName, false);
	}

	public PackageRelationshipSelector(URI pSourceURI,
			PackagePartName pRelationshipPartName,
			boolean pIsAllRelationshipsIncluded) {
		sourceURI = pSourceURI;
		relationshipPartName = pRelationshipPartName;
		relationshipIdentifiers = new Vector<RelationshipIdentifier>();
		this.isAllRelationshipsIncluded = pIsAllRelationshipsIncluded;
	}

}
