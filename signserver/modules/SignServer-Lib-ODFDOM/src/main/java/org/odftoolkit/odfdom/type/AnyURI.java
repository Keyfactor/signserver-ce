/************************************************************************
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
 * 
 * Copyright 2008 Sun Microsystems, Inc. All rights reserved.
 * Copyright 2009 IBM. All rights reserved.
 * 
 * Use is subject to license terms.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0. You can also
 * obtain a copy of the License at http://odftoolkit.org/docs/license.txt
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ************************************************************************/
package org.odftoolkit.odfdom.type;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class represents the in OpenDocument format used data type {@odf.datatype anyURI} 
 */
public class AnyURI implements OdfDataType {

	private URI mURI;

	/**
	 * Construct an newly AnyURI object that represents the specified URI value
	 *
	 * @param uri
	 *            the value to be represented by the AnyURI Object
	 * @throws IllegalArgumentException if the given argument is not a valid AnyURI
	 */
	public AnyURI(URI uri) throws IllegalArgumentException {
		if (uri == null) {
			throw new IllegalArgumentException(
					"parameter can not be null for AnyURI");
		}

		// validate 'anyURI' type which is defined in W3C schema
		// http://www.w3.org/TR/xmlschema-2/#anyURI
		if (!W3CSchemaType.isValid("anyURI", URITransformer.decodePath(uri.toString()))) {
			Logger.getLogger(AnyURI.class.getName()).log(Level.SEVERE, "parameter is invalidate for datatype AnyURI");
			throw new IllegalArgumentException(
					"parameter is invalidate for datatype anyURI");
		}
		mURI = uri;
	}

	/**
	 * Returns a String Object representing this AnyURI's value
	 *
	 * @return return a string representation of the value of this AnyURI object
	 */
	@Override
	public String toString() {
		return URITransformer.decodePath(mURI.toString());
	}

	/**
	 * Returns an AnyURI instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return an AnyURI instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid AnyURI
	 */
	public static AnyURI valueOf(String stringValue)
			throws IllegalArgumentException {
		if (stringValue == null) {
			throw new IllegalArgumentException(
					"parameter can not be null for AnyURI");
		}
		try {
			URI uri = new URI(URITransformer.encodePath(stringValue).toString());
			return new AnyURI(uri);
		} catch (URISyntaxException ex) {
			Logger.getLogger(AnyURI.class.getName()).log(Level.SEVERE,
					"parameter is invalidate for datatype anyURI", ex);
			throw new IllegalArgumentException(
					"parameter is invalidate for datatype anyURI");
		}
	}

	/**
	 * get java.net.URI from AnyURI
	 *
	 * @return java.net.URI returned from this AnyURI
	 */
	public URI getURI() {
		return mURI;
	}

	/**
	 * check if the specified URI instance is a valid {@odf.datatype anyURI} data type
	 *
	 * @param uri
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype anyURI} data type false
	 *         otherwise
	 */
	public static boolean isValid(URI uri) {
		boolean isValid = false;
		if (uri != null) {
			isValid = W3CSchemaType.isValid("anyURI", uri.toString());
		}
		return isValid;
	}

    /**
     * Encode path to be used as path component segments in URI.
     *
     * <p>Creates a String that can be used as a sequence of one or more
     * path components in an URI from a path that uses a slash
     * character as a path separator and where the segements do not use
     * any URI encoding rules.</p>
     *
     * <p>The <b>/</b> characters (delimiting the individual path_segments)
     * are left unchanged.</p>
     *
     * @param path A path that is not using URI encoding rules.
     * @return A path that is using URI encoding rules.
     *
     * @see #decodePath(String)
     */
    public static String encodePath(String path) {
        return URITransformer.encodePath(path);
    }

    /**
     * Decode path component segments in URI.
     *
     * <p>Creates a path that uses a slash character as a path separator
     * and where the segments do not use any URI encoding
     * from a String that is used as a sequence of one or more
     * path components in an URI where the path segments do use
     * URI encoding rules.</p>
     *
     * <p>The <b>/</b> characters (delimiting the individual path_segments)
     * are left unchanged.</p>
     *
     * @param path A path that is using URI encoding rules.
     * @return A path that is not using URI encoding rules.
     *
     * @see #encodePath(String)
     *
     */
    public static String decodePath(String path) {
        return URITransformer.decodePath(path);
    }
}
