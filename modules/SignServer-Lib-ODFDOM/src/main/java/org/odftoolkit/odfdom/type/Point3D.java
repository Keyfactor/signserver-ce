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
 * This class represents the in OpenDocument format used data type {@odf.datatype point3D}
 */
public class Point3D implements OdfDataType {

	private String mPoint3D;

	/**
	 * Construct Point3D by the parsing the given string
	 *
	 * @param point3D
	 *            The String to be parsed into Point3D
	 * @throws IllegalArgumentException if the given argument is not a valid Point3D
	 */
	public Point3D(String point3D) throws IllegalArgumentException {
		if ((point3D == null) || (!point3D.matches("^\\([ ]*-?([0-9]+(\\.[0-9]*)?|\\.[0-9]+)((cm)|(mm)|(in)|(pt)|(pc))([ ]+-?([0-9]+(\\.[0-9]*)?|\\.[0-9]+)((cm)|(mm)|(in)|(pt)|(pc))){2}[ ]*\\)$"))) {
			throw new IllegalArgumentException("parameter is invalidate for datatype Point3D");
		}
		mPoint3D = point3D;
	}

	/**
	 * Returns a String Object representing this Point3D's value
	 *
	 * @return return a string representation of the value of this Point3D
	 *         object
	 */
	@Override
	public String toString() {
		return mPoint3D;
	}

	/**
	 * Returns a Point3D instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a Point3D instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid Point3D
	 */
	public static Point3D valueOf(String stringValue)
			throws IllegalArgumentException {
		return new Point3D(stringValue);
	}

	/**
	 * check if the specified String instance is a valid {@odf.datatype point3D} data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype point3D} data type
	 *         false otherwise
	 */
	public static boolean isValid(String stringValue) {
		if ((stringValue == null) || (!stringValue.matches("^\\([ ]*-?([0-9]+(\\.[0-9]*)?|\\.[0-9]+)((cm)|(mm)|(in)|(pt)|(pc))([ ]+-?([0-9]+(\\.[0-9]*)?|\\.[0-9]+)((cm)|(mm)|(in)|(pt)|(pc))){2}[ ]*\\)$"))) {
			return false;
		} else {
			return true;
		}
	}
}
