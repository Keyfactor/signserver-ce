/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.signserver.module.odfsigner;


/*
 * identifies a part by full path and media type 
 * NOTE : whereas part path alone is sufficient media type is used in reference generation (text/xml parts are transformed using c14n, others not), so included it is
 * 
 * @author Aziz Göktepe
 */
public class ODFPartIdentifier {

	String fullPath;
	String mediaType;

	public String getFullPath() {
		return fullPath;
	}

	public String getMediaType() {
		return mediaType;
	}

	public ODFPartIdentifier(String pFullPath, String pMediaType) {
		fullPath = pFullPath;
		mediaType = pMediaType;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof ODFPartIdentifier ) {
			ODFPartIdentifier  partIdent = (ODFPartIdentifier) obj;
			return this.getMediaType().equals(partIdent.getMediaType())
					&& this.getFullPath().equals(partIdent.getFullPath());
		}

		return false;
	}
}
