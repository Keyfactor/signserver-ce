package org.signserver.module.ooxmlsigner;

import java.net.URI;

/*
 * identifies a part by part URI and content type 
 * NOTE : whereas part URI alone is sufficient content type is used in reference generation, so included it is
 */
public class PartIdentifier {

	URI partURI;
	String contentType;

	public URI getPartURI() {
		return partURI;
	}

	public String getContentType() {
		return contentType;
	}

	public PartIdentifier(URI pPartURI, String pContentType) {
		partURI = pPartURI;
		contentType = pContentType;
	}
	
	@Override
	public boolean equals(Object obj) {
		if(obj instanceof PartIdentifier)
		{
			PartIdentifier partIdent = (PartIdentifier)obj;
			return this.getContentType().equals(partIdent.getContentType()) 
				&& this.getPartURI().toString().equals(partIdent.getPartURI().toString()); 
		}
		
		return false;
	}
}
