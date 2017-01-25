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
 * This class represents the in OpenDocument format used data type {@odf.datatype language}
 */
public class Language implements OdfDataType {

	private String mLanguage;

	/**
	 * Construct Language by the parsing the given string
	 *
	 * @param language
	 *            The String to be parsed into Language
	 * @throws IllegalArgumentException if the given argument is not a valid Language
	 */
	public Language(String language) throws IllegalArgumentException {
		if (language == null) {
			throw new IllegalArgumentException("parameter can not be null for Language");
		}
		if (!W3CSchemaType.isValid("language", language)) {
			throw new IllegalArgumentException(
					"parameter is invalidate for datatype Language");
		}
		mLanguage = language;
	}

	/**
	 * Returns a String Object representing this Language's value
	 *
	 * @return return a string representation of the value of this Language
	 *         object
	 */
	@Override
	public String toString() {
		return mLanguage;
	}

	/**
	 * Returns a Language instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a Language instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid Language
	 */
	public static Language valueOf(String stringValue)
			throws IllegalArgumentException {
		return new Language(stringValue);
	}

	/**
	 * check if the specified String instance is a valid {@odf.datatype language} data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype language} data type
	 *         false otherwise
	 */
	public static boolean isValid(String stringValue) {
		if (stringValue == null) {
			return true;
		} else {
			return W3CSchemaType.isValid("language", stringValue);
		}
	}
}
