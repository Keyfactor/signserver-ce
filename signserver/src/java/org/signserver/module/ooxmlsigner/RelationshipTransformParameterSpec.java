package org.signserver.module.ooxmlsigner;

import java.util.List;

import javax.xml.crypto.dsig.spec.TransformParameterSpec;

public class RelationshipTransformParameterSpec implements
		TransformParameterSpec {

	List<String> relationShipIdsToInclude;
	public List<String> getRelationShipIdsToInclude() {
		return relationShipIdsToInclude;
	}
	public void setRelationShipIdsToInclude(List<String> relationShipIdsToInclude) {
		this.relationShipIdsToInclude = relationShipIdsToInclude;
	}
	
	public RelationshipTransformParameterSpec(List<String> pRelationShipIdsToInclude) {
		relationShipIdsToInclude = pRelationShipIdsToInclude;
	}
	
}
