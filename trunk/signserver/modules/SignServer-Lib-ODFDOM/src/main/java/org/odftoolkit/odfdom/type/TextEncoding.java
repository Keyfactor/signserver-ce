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
 * This class represents the in OpenDocument format used data type {@odf.datatype textEncoding}
 */
public class TextEncoding implements OdfDataType {

	private String mTextEncoding;

	/**
	 * Construct TextEncoding by the parsing the given string
	 *
	 * @param textEncoding
	 *            The String to be parsed into TextEncoding
	 * @throws IllegalArgumentException if the given argument is not a valid TextEncoding
	 */
	public TextEncoding(String textEncoding) throws IllegalArgumentException {
		if ((textEncoding == null) || (!textEncoding.matches("^[A-Za-z][A-Za-z0-9._\\-]*$"))) {
			throw new IllegalArgumentException(
					"parameter is invalidate for datatype TextEncoding");
		}
		mTextEncoding = textEncoding;
	}

	/**
	 * Returns a String Object representing this TextEncoding's value
	 *
	 * @return return a string representation of the value of this TextEncoding
	 *         object
	 */
	@Override
	public String toString() {
		return mTextEncoding;
	}

	/**
	 * Returns a TextEncoding instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a TextEncoding instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid TextEncoding
	 */
	public static TextEncoding valueOf(String stringValue)
			throws IllegalArgumentException {
		return new TextEncoding(stringValue);
	}

	/**
	 * check if the specified String instance is a valid {@odf.datatype textEncoding} data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype textEncoding} data type
	 *         false otherwise
	 */
	public static boolean isValid(String stringValue) {
		if ((stringValue == null) || (!stringValue.matches("^[A-Za-z][A-Za-z0-9._\\-]*$"))) {
			return false;
		} else {
			return true;
		}
	}
}
