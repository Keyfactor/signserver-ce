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

/**
 * This class represents the in OpenDocument format used data type {@odf.datatype IDREF}
 */
public class IDREF implements OdfDataType {

	private String mIdRef;

	/**
	 * Construct IDREF by the parsing the given string
	 *
	 * @param idRef The String to be parsed into IDREF
	 * @throws IllegalArgumentException if the given argument is not a valid IDREF
	 */
	public IDREF(String idRef) throws IllegalArgumentException {
		if (idRef == null) {
			throw new IllegalArgumentException(
					"parameter can not be null for IDREF");
		}
		// validate 'IDREF' type which is defined in W3C schema
		// http://www.w3.org/TR/xmlschema-2/#IDREF
		if (!W3CSchemaType.isValid("IDREF", idRef)) {
			throw new IllegalArgumentException("parameter is invalidate for datatype IDREF");

		}
		mIdRef = idRef;
	}

	/**
	 * Returns a String Object representing this IDREF's value
	 *
	 * @return return a string representation of the value of this IDREF object
	 */
	@Override
	public String toString() {
		return mIdRef;
	}

	/**
	 * Returns an IDREF instance representing the specified String value
	 *
	 * @param stringValue a String value
	 * @throws IllegalArgumentException if the given argument is not a valid IDREF
	 * @return return an IDREF instance representing stringValue
	 */
	public static IDREF valueOf(String stringValue)
			throws IllegalArgumentException {
		return new IDREF(stringValue);
	}

	/**
	 * check if the specified String instance is a valid {@odf.datatype IDREF} data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype IDREF} data type false
	 *         otherwise
	 */
	public static boolean isValid(String stringValue) {
		if (stringValue == null) {
			return true;
		} else {
			return W3CSchemaType.isValid("IDREF", stringValue);
		}
	}
}
