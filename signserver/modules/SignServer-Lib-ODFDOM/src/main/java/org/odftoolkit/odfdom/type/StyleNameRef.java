/************************************************************************
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
 * 
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
 * This class represents the in OpenDocument format used data type {@odf.datatype styleNameRef}
 */
public class StyleNameRef implements OdfDataType {

	String mStyleNameRef;

	/**
	 * Construct StyleNameRef by the parsing the given string
	 *
	 * @param styleNameRef The String to be parsed into StyleNameRef
	 * @throws IllegalArgumentException if the given argument is not a valid StyleNameRef
	 */
	public StyleNameRef(String styleNameRef) throws IllegalArgumentException {

		if (styleNameRef == null) {
			throw new IllegalArgumentException(
					"parameter can not be null for StyleNameRef");
		}
		if (styleNameRef.length() == 0) {
			mStyleNameRef = styleNameRef;
			return;
		}
		// validate 'NCName' type which is defined in W3C schema
		// http://www.w3.org/TR/xmlschema-2/#NCName
		if (!W3CSchemaType.isValid("NCName", styleNameRef)) {
			throw new IllegalArgumentException(
					"parameter is invalidate for datatype StyleNameRef");
		}
		mStyleNameRef = styleNameRef;
	}

	/**
	 * Returns a String Object representing this StyleNameRef's value
	 *
	 * @return return a string representation of the value of this StyleNameRef
	 *         object
	 */
	@Override
	public String toString() {
		return mStyleNameRef;
	}

	/**
	 * Returns a StyleNameRef instance representing the specified String value
	 *
	 * @param stringValue a String value which can construct an OdfStyleNameRef
	 * @return a StyleNameRef instance representing stringValue
	 * @throws IllegalArgumentException
	 */
	public static StyleNameRef valueOf(String stringValue)
			throws IllegalArgumentException {
		return new StyleNameRef(stringValue);
	}

	/**
	 * check if the specified String is a valid {@odf.datatype styleNameRef} data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype styleNameRef} data type
	 *         false otherwise
	 */
	public static boolean isValid(String stringValue) {
		if (stringValue == null) {
			return false;
		} else if (stringValue.length() == 0) {
			return true;
		} else {
			return W3CSchemaType.isValid("NCName", stringValue);
		}
	}
}
