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
 * This class represents the in OpenDocument format used data type {@odf.datatype relativeLength}
 */
public class RelativeLength implements OdfDataType {

	private String mLength;

	/**
	 * Construct RelativeLength by the parsing the given string
	 *
	 * @param length
	 *            The String to be parsed into RelativeLength
	 * @throws NumberFormatException if the given argument is not a valid RelativeLength
	 */
	public RelativeLength(String length) throws NumberFormatException {
		if ((length == null) || (!length.matches("^[0-9]+\\*$"))) {
			throw new NumberFormatException(
					"parameter is invalidate for datatype RelativeLength");
		}
		mLength = length;
	}

	/**
	 * Returns a String Object representing this RelativeLength's value
	 *
	 * @return return a string representation of the value of this
	 *         RelativeLength object
	 */
	@Override
	public String toString() {
		return mLength;
	}

	/**
	 * Returns an RelativeLength instance representing the specified String
	 * value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return an RelativeLength instance representing stringValue
	 */
	public static RelativeLength valueOf(String stringValue)
			throws NumberFormatException {
		return new RelativeLength(stringValue);
	}

	/**
	 * check if the specified String instance is a valid {@odf.datatype relativeLength} data
	 * type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype relativeLength} data
	 *         type false otherwise
	 */
	public static boolean isValid(String stringValue) {
		if ((stringValue == null) || (!stringValue.matches("^[0-9]+\\*$"))) {
			return false;
		} else {
			return true;
		}
	}
}
