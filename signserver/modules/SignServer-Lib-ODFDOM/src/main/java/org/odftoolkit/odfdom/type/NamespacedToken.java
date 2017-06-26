/************************************************************************
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
 * 
 * Copyright 2008 Sun Microsystems, Inc. All rights reserved.
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
 * This class represents the in OpenDocument format used data type {@odf.datatype namespacedToken}
 */
public class NamespacedToken implements OdfDataType {

	private String mNamespacedToken;

	/**
	 * Construct NamespacedToken by the parsing the given string
	 *
	 * @param namespacedToken
	 *            The String to be parsed into NamespacedToken
	 * @throws IllegalArgumentException if the given argument is not a valid NamespacedToken
	 */
	public NamespacedToken(String namespacedToken) throws IllegalArgumentException {
		if ((namespacedToken == null) || (!namespacedToken.matches("^[0-9a-zA-Z_]+:[0-9a-zA-Z._\\-]+$"))) {
			throw new IllegalArgumentException(
					"parameter is invalidate for datatype NamespacedToken");
		}
		mNamespacedToken = namespacedToken;
	}

	/**
	 * Returns a String Object representing this NamespacedToken's value
	 *
	 * @return return a string representation of the value of this
	 *         NamespacedToken object
	 */
	@Override
	public String toString() {
		return mNamespacedToken;
	}

	/**
	 * Returns a NamespacedToken instance representing the specified String
	 * value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a NamespacedToken instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid NamespacedToken
	 */
	public static NamespacedToken valueOf(String stringValue)
			throws IllegalArgumentException {
		return new NamespacedToken(stringValue);
	}

	/**
	 * check if the specified String instance is a valid {@odf.datatype namespacedToken} data
	 * type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype namespacedToken} data
	 *         type false otherwise
	 */
	public static boolean isValid(String stringValue) {
		if ((stringValue == null) || (!stringValue.matches("^[0-9a-zA-Z_]+:[0-9a-zA-Z._\\-]+$"))) {
			return false;
		} else {
			return true;
		}
	}
}
