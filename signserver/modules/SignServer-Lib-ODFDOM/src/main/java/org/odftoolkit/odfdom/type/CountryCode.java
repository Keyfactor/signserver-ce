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
 * This class represents the in OpenDocument format used data type {@odf.datatype countryCode}
 */
public class CountryCode implements OdfDataType {

	private String mCountryCode;

	/**
	 * Construct CountryCode by the parsing the given string
	 *
	 * @param countryCode
	 *            The String to be parsed into CountryCode
	 * @throws IllegalArgumentException if the given argument is not a valid CountryCode
	 */
	public CountryCode(String countryCode) throws IllegalArgumentException {
		if ((countryCode == null) || (!countryCode.matches("^[A-Za-z0-9]{1,8}$"))) {
			throw new IllegalArgumentException("parameter is invalidate for datatype CountryCode");
		}
		// validate 'token' type which is defined in W3C schema
		// http://www.w3.org/TR/xmlschema-2/#token
		if (!W3CSchemaType.isValid("token", countryCode)) {
			throw new IllegalArgumentException("parameter is invalidate for datatype CountryCode");
		}
		mCountryCode = countryCode;
	}

	/**
	 * Returns a String Object representing this CountryCode's value
	 *
	 * @return return a string representation of the value of this CountryCode
	 *         object
	 */
	@Override
	public String toString() {
		return mCountryCode;
	}

	/**
	 * Returns a CountryCode instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a CountryCode instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid CountryCode
	 */
	public static CountryCode valueOf(String stringValue)
			throws IllegalArgumentException {
		return new CountryCode(stringValue);
	}

	/**
	 * check if the specified String is a valid {@odf.datatype countryCode} data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype countryCode} data type
	 *         false otherwise
	 */
	public static boolean isValid(String stringValue) {
		if (stringValue == null || !stringValue.matches("^[A-Za-z0-9]{1,8}$")) {
			return false;
		} else {
			return W3CSchemaType.isValid("token", stringValue);
		}
	}
}
