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
 * This class represents the in OpenDocument format used data type {@odf.datatype points}
 */
public class Points implements OdfDataType {

	private String mPoints;

	/**
	 * Construct Points by the parsing the given string
	 *
	 * @param points The String to be parsed into Points
	 *
	 * @throws IllegalArgumentException if the given argument is not a valid Pointes
	 */
	public Points(String points) throws IllegalArgumentException {
		if ((points == null) || (!points.matches("^-?[0-9]+,-?[0-9]+([ ]+-?[0-9]+,-?[0-9]+)*$"))) {
			throw new IllegalArgumentException(
					"parameter is invalidate for datatype Points");
		}
		mPoints = points;
	}

	/**
	 * Returns a String Object representing this Points's value
	 *
	 * @return return a string representation of the value of this Points object
	 */
	@Override
	public String toString() {
		return mPoints;
	}

	/**
	 * Returns a Points instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a Points instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid Pointes
	 */
	public static Points valueOf(String stringValue) throws IllegalArgumentException {
		return new Points(stringValue);
	}

	/**
	 * check if the specified String instance is a valid {@odf.datatype points} data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype points} data type false
	 *         otherwise
	 */
	public static boolean isValid(String stringValue) {
		if ((stringValue == null) || (!stringValue.matches("^-?[0-9]+,-?[0-9]+([ ]+-?[0-9]+,-?[0-9]+)*$"))) {
			return false;
		} else {
			return true;
		}
	}
}
