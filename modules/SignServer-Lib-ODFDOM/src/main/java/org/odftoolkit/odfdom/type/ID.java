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
 * This class represents the in OpenDocument format used data type {@odf.datatype ID}
 */
public class ID implements OdfDataType {

	private String mId;

	/**
	 * Construct ID by the parsing the given string
	 *
	 * @param id    The String to be parsed into ID
	 * @throws IllegalArgumentException if the given argument is not a valid ID
	 */
	public ID(String id) throws IllegalArgumentException {
		if (id == null) {
			throw new IllegalArgumentException("parameter can not be null for ID");
		}

		// validate 'ID' type which is defined in W3C schema
		// http://www.w3.org/TR/xmlschema-2/#ID
		if (!W3CSchemaType.isValid("ID", id)) {
			throw new IllegalArgumentException("parameter is invalidate for datatype ID");
		}
		mId = id;
	}

	/**
	 * Returns a String Object representing this ID's value
	 *
	 * @return return a string representation of the value of this ID object
	 */
	@Override
	public String toString() {
		return mId;
	}

	/**
	 * Returns an ID instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return an ID instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid ID
	 */
	public static ID valueOf(String stringValue) throws IllegalArgumentException {
		return new ID(stringValue);
	}

	/**
	 * check if the specified String instance is a valid {@odf.datatype ID} data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype ID} data type false
	 *         otherwise
	 */
	public static boolean isValid(String stringValue) {
		if (stringValue == null) {
			return true;
		} else {
			return W3CSchemaType.isValid("ID", stringValue);
		}
	}
}
