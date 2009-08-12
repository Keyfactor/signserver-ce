package org.openxml4j.signaturehelpers;

public class RelationshipIdentifier {

	PackageRelationshipSelectorType selectorType;
	String selectionCriteria;

	public PackageRelationshipSelectorType getSelectorType() {
		return selectorType;
	}

	public String getSelectionCriteria() {
		return selectionCriteria;
	}

	public RelationshipIdentifier(
			PackageRelationshipSelectorType pSelectorType,
			String pSelectionCriteria) {
		selectorType = pSelectorType;
		selectionCriteria = pSelectionCriteria;
	}
	
	@Override
	public String toString() {
		return "Selection Criteria : " + selectionCriteria + " Selector Type : " + selectorType.toString();
	}
}
