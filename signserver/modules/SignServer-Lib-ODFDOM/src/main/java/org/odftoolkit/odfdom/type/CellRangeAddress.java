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
 * This class represents the in OpenDocument format used data type {@odf.datatype cellRangeAddress}
 */
public class CellRangeAddress implements OdfDataType {

	private String mCellRangeAddress;

	/**
	 * Construct CellRangeAddress by the parsing the given string
	 *
	 * @param cellRangeAddress
	 *            The String to be parsed into CellRangeAddress
	 * @throws IllegalArgumentException if the given argument is not a valid CellRangeAddress
	 */
	public CellRangeAddress(String cellRangeAddress)
			throws IllegalArgumentException {
		if ((cellRangeAddress == null) || (!(cellRangeAddress.matches("^(\\$?([^\\. ']+|'([^']|'')+'))?\\.\\$?[A-Z]+\\$?[0-9]+(:(\\$?([^\\. ']+|'([^']|'')+'))?\\.\\$?[A-Z]+\\$?[0-9]+)?$") || cellRangeAddress.matches("^(\\$?([^\\. ']+|'([^']|'')+'))?\\.\\$?[0-9]+:(\\$?([^\\. ']+|'([^']|'')+'))?\\.\\$?[0-9]+$") || cellRangeAddress.matches("^(\\$?([^\\. ']+|'([^']|'')+'))?\\.\\$?[A-Z]+:(\\$?([^\\. ']+|'([^']|'')+'))?\\.\\$?[A-Z]+$")))) {
			throw new IllegalArgumentException(
					"parameter is invalidate for datatype CellRangeAddress");
		}
		mCellRangeAddress = cellRangeAddress;
	}

	// TODO: Should a cell address stay a string?
	/**
	 * Returns a String Object representing this CellRangeAddress's value
	 *
	 * @return return a string representation of the value of this
	 *         CellRangeAddress object
	 */
	@Override
	public String toString() {
		return mCellRangeAddress;
	}

	/**
	 * Returns a CellRangeAddress instance representing the specified String
	 * value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a CellRangeAddress instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid CellRangeAddress
	 */
	public static CellRangeAddress valueOf(String stringValue)
			throws IllegalArgumentException {
		return new CellRangeAddress(stringValue);
	}

	/**
	 * check if the specified String is a valid {@odf.datatype cellRangeAddress} data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype cellRangeAddress} data
	 *         type false otherwise
	 */
	public static boolean isValid(String stringValue) {
		if ((stringValue == null) || (!(stringValue.matches("^(\\$?([^\\. ']+|'([^']|'')+'))?\\.\\$?[A-Z]+\\$?[0-9]+(:(\\$?([^\\. ']+|'([^']|'')+'))?\\.\\$?[A-Z]+\\$?[0-9]+)?$") || stringValue.matches("^(\\$?([^\\. ']+|'([^']|'')+'))?\\.\\$?[0-9]+:(\\$?([^\\. ']+|'([^']|'')+'))?\\.\\$?[0-9]+$") || stringValue.matches("^(\\$?([^\\. ']+|'([^']|'')+'))?\\.\\$?[A-Z]+:(\\$?([^\\. ']+|'([^']|'')+'))?\\.\\$?[A-Z]+$")))) {
			return false;
		} else {
			return true;
		}
	}
}
