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
 * This class represents the in OpenDocument format used data type {@odf.datatype formula}
 */
public class Formula implements OdfDataType {

	private String mFormula;

	/**
	 * Construct Formula by the parsing the given string
	 *
	 * @param formula  The String to be parsed into Formula
	 * @throws IllegalArgumentException if the given argument is not a valid Formula
	 */
	public Formula(String formula) throws IllegalArgumentException {
		if (formula == null) {
			throw new IllegalArgumentException(
					"parameter can not be null for Formula");
		}
		mFormula = formula;
	}

	/**
	 * Returns a String Object representing this Formula's value
	 *
	 * @return return a string representation of the value of this Formula
	 *         object
	 */
	@Override
	public String toString() {
		return mFormula;
	}

	/**
	 * Returns a Formula instance representing the specified String value
	 *
	 * @param stringValue   a String value
	 * @return return a Formula instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid Formula
	 */
	public static Formula valueOf(String stringValue)
			throws IllegalArgumentException {
		return new Formula(stringValue);
	}

	/**
	 * check if the specified String is a valid {@odf.datatype formula} data type
	 *
	 * @param stringValue   the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype formula} data type
	 *         false otherwise
	 */
	public static boolean isValid(String stringValue) {
		if (stringValue == null) {
			return false;
		}

		return true;
	}
}
