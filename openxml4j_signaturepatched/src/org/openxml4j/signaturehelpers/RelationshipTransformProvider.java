package org.openxml4j.signaturehelpers;

import java.security.AccessController;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;

public final class RelationshipTransformProvider extends Provider {

	public static String RelationShipTransformAlgorithm = "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";
	
	@SuppressWarnings("unchecked")
	public RelationshipTransformProvider() {
		super("OOXML Relationship Transform", 0.0, "");

		final Map map = new HashMap();

		map.put("TransformService."
				+ RelationshipTransformProvider.RelationShipTransformAlgorithm,
				"org.openxml4j.signaturehelpers.RelationshipTransformService");

		map.put("TransformService."
				+ RelationshipTransformProvider.RelationShipTransformAlgorithm
				+ " MechanismType", "DOM");

		AccessController.doPrivileged(new java.security.PrivilegedAction() {
			public Object run() {
				putAll(map);
				return null;
			}
		});

	}

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

}
