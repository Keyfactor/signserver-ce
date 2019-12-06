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
 * This class represents the in OpenDocument format used data type {@odf.datatype nonNegativeInteger}
 */
public class NonNegativeInteger implements OdfDataType {

	private int mN;

	/**
	 * Allocates a NonNegativeInteger object representing the n argument
	 *
	 * @param n
	 *            the value of the NonNegativeInteger
	 * @throws NumberFormatException if the given argument is not a valid NonNegativeInteger
	 */
	public NonNegativeInteger(int n) throws NumberFormatException {
		if (n < 0) {
			throw new NumberFormatException("parameter is invalidate for datatype NonNegativeInteger");
		}
		mN = n;
	}

	/**
	 * Returns a String Object representing this NonNegativeInteger's value
	 *
	 * @return return a string representation of the value of this
	 *         NonNegativeInteger object
	 */
	@Override
	public String toString() {
		return Integer.toString(mN);
	}

	/**
	 * Returns a NonNegativeInteger instance representing the specified String
	 * value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a NonNegativeInteger instance representing stringValue
	 * @throws NumberFormatException if the given argument is not a valid NonNegativeInteger
	 */
	public static NonNegativeInteger valueOf(String stringValue)
			throws NumberFormatException {
		String aTmp = stringValue.trim();
		int n = Integer.valueOf(aTmp);
		return new NonNegativeInteger(n);
	}

	/**
	 * Returns the value of this NonNegativeInteger object as a int primitive
	 *
	 * @return the primitive int value of this NonNegativeInteger object.
	 */
	public int intValue() {
		return mN;
	}

	/**
	 * check if the specified Integer instance is a valid {@odf.datatype nonNegativeInteger}
	 * data type
	 *
	 * @param integerValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype nonNegativeInteger}
	 *         data type false otherwise
	 */
	public static boolean isValid(Integer integerValue) {
		if (integerValue == null) {
			return false;
		}
		if (integerValue.intValue() < 0) {
			return false;
		} else {
			return true;
		}
	}
}
