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
 * This class represents the in OpenDocument format used data type {@odf.datatype vector3D}
 */
public class Vector3D implements OdfDataType {

	private String mVector3D;

	/**
	 * Construct Vector3D by the parsing the given string
	 *
	 * @param vector3D
	 *            The String to be parsed into Vector3D
	 */
	public Vector3D(String vector3D) {
		if ((vector3D == null) || (!vector3D.matches("^\\([ ]*-?([0-9]+(\\.[0-9]*)?|\\.[0-9]+)([ ]+-?([0-9]+(\\.[0-9]*)?|\\.[0-9]+)){2}[ ]*\\)$"))) {
			throw new IllegalArgumentException("parameter is invalidate for datatype Vector3D");
		}
		mVector3D = vector3D;
	}

	/**
	 * Returns a String Object representing this Vector3D's value
	 *
	 * @return return a string representation of the value of this Vector3D
	 *         object
	 */
	@Override
	public String toString() {
		return mVector3D;
	}

	/**
	 * Returns a Vector3D instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a Vector3D instance representing stringValue
	 */
	public static Vector3D valueOf(String stringValue) {
		return new Vector3D(stringValue);
	}

	/**
	 * check if the specified String instance is a valid {@odf.datatype vector3D} data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype vector3D} data type
	 *         false otherwise
	 */
	public static boolean isValid(String stringValue) {
		if ((stringValue == null) || (!stringValue.matches("^\\([ ]*-?([0-9]+(\\.[0-9]*)?|\\.[0-9]+)([ ]+-?([0-9]+(\\.[0-9]*)?|\\.[0-9]+)){2}[ ]*\\)$"))) {
			return false;
		} else {
			return true;
		}
	}
}
