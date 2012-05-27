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
 * This class represents the in OpenDocument format used data type {@odf.datatype positiveLength}
 */
public class PositiveLength extends Length {

	/**
	 * Construct PositiveLength by the parsing the given string
	 *
	 * @param length
	 *            The String to be parsed into PositiveLength
	 * @throws NumberFormatException if the given argument is not a valid PostitiveLength
	 */
	public PositiveLength(String length) throws NumberFormatException {
		super(length);
		if ((length == null) || (!length.matches("^([0-9]*[1-9][0-9]*(\\.[0-9]*)?|0+\\.[0-9]*[1-9][0-9]*|\\.[0-9]*[1-9][0-9]*)((cm)|(mm)|(in)|(pt)|(pc)|(px))$"))) {
			throw new NumberFormatException(
					"parameter is invalidate for datatype PositiveLength");
		}
	}


	/**
	 * Returns a PositiveLength instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a PositiveLength instance representing stringValue
	 * @throws NumberFormatException if the given argument is not a valid PostitiveLength
	 */
	public static PositiveLength valueOf(String stringValue)
			throws NumberFormatException {
		return new PositiveLength(stringValue);
	}

	/**
	 * check if the specified String instance is a valid {@odf.datatype positiveLength} data
	 * type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype positiveLength} data
	 *         type false otherwise
	 */
	public static boolean isValid(String stringValue) {
		if ((stringValue == null) || (!stringValue.matches("^([0-9]*[1-9][0-9]*(\\.[0-9]*)?|0+\\.[0-9]*[1-9][0-9]*|\\.[0-9]*[1-9][0-9]*)((cm)|(mm)|(in)|(pt)|(pc)|(px))$"))) {
			return false;
		} else {
			return true;
		}
	}
}
