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
 *This class represents the in OpenDocument format used data type {@odf.datatype targetFrameName}
 * 
 */
public enum TargetFrameName implements OdfDataType {

	_SELF("_self"), _BLANK("_blank"), _PARENT("_parent"), _TOP("_top");
	private String mValue;

	TargetFrameName(String aValue) {
		mValue = aValue;
	}

	/**
	 *gets the name of this enum.
	 *
	 *@return return the name of TargetFrameNameType
	 */
	@Override
	public String toString() {
		return mValue;
	}

	/**
	 *enum to String, gets the name of this enum constant as a string.
	 *
	 *@param aEnum
	 *            the constant of TargetFrameName
	 *@return return the name of TargetFrameName
	 */
	public static String toString(TargetFrameName aEnum) {
		return aEnum.toString();
	}

	/**
	 *String to enum, turns a String into its corresponding enum constant
	 *
	 *@param stringValue
	 *            the name of OdfTargetFrameNameType
	 *@return return the constant of OdfTargetFrameNameType
	 */
	public static TargetFrameName enumValueOf(String stringValue) {
		for (TargetFrameName aIter : values()) {
			if (stringValue.equals(aIter.toString())) {
				return aIter;
			}
		}
		return null;
	}

	/**
	 * check if the specified String is a valid {@odf.datatype targetFrameName} data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype targetFrameName} data
	 *         type false otherwise
	 */
	public static boolean isValid(String stringValue) {
		if (stringValue == null) {
			return false;
		}

		if (TargetFrameName.enumValueOf(stringValue) != null) {
			return true;
		} else {
			return false;
		}
	}
}
