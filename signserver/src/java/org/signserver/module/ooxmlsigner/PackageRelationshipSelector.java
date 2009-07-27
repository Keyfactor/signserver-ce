package org.signserver.module.ooxmlsigner;

import java.net.URI;
import java.util.List;
import java.util.Vector;

import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.opc.PackagePartName;

/*
 * Summary: Defines PackageRelationship criteria to select part-level or
 * package-level relationships.
 */
public class PackageRelationshipSelector {
	URI sourceURI;
	PackagePartName relationshipPartName;
	List<RelationshipIdentifier> relationshipIdentifiers;

	public URI getSourceURI() {
		return sourceURI;
	}

	/*
	 * gets the package part name of the current relationship part
	 */
	public PackagePartName getRelationshipPartName()
			throws InvalidFormatException {

		return relationshipPartName;
	}

	public List<RelationshipIdentifier> getRelationshipIdentifiers() {
		return relationshipIdentifiers;
	}

	public void addRelationshipIdentifier(
			RelationshipIdentifier pRelationshipIdentifier) throws Exception {
		for (RelationshipIdentifier tempRelId : relationshipIdentifiers) {
			if (tempRelId.selectionCriteria
					.equals(pRelationshipIdentifier.selectionCriteria)
					&& tempRelId.selectorType
							.equals(pRelationshipIdentifier.selectorType))
				throw new Exception("Relationship Identifier already added. Relationship Identifier to add: " + pRelationshipIdentifier);
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
		sourceURI = pSourceURI;
		relationshipPartName = pRelationshipPartName;
		relationshipIdentifiers = new Vector<RelationshipIdentifier>();
	}

}
