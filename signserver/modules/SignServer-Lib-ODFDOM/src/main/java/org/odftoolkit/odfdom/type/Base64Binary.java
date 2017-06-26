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

import org.apache.xerces.impl.dv.util.Base64;

/**
 * This class represents the in OpenDocument format used data type {@odf.datatype base64Binary}
 */
public class Base64Binary implements OdfDataType {

	private byte[] mByteList;

	/**
	 * Construct an newly Base64Binary object that represents the specified
	 * byte[] value
	 *
	 * @param bytes
	 *            the value to be represented by the Base64Binary Object
	 * @throws NumberFormatException If the parameter is not a valid Base64Binary.
	 *
	 */
	public Base64Binary(byte[] bytes) throws NumberFormatException {
		if (bytes == null) {
			throw new NumberFormatException("parameter can not be null for Base64Binary");
		}

		// validate 'base64Binary' type which is defined in W3C schema
		// http://www.w3.org/TR/xmlschema-2/#base64Binary
		if (!W3CSchemaType.isValid("base64Binary", Base64.encode(bytes))) {
			throw new NumberFormatException("parameter is invalidate for datatype base64Binary");
		}
		mByteList = bytes;
	}

	/**
	 * Returns a String Object representing this Base64Binary's value
	 *
	 * @return return a string representation of the value of this Base64Binary
	 *         object
	 */
	@Override
	public String toString() {
		return Base64.encode(mByteList);
	}

	/**
	 * Returns a Base64Binary instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a Base64Binary instance representing stringValue
	 * @throws NumberFormatException If the parameter is not a valid Base64Binary.
	 */
	public static Base64Binary valueOf(String stringValue)
			throws NumberFormatException {
		if (stringValue == null) {
			throw new NumberFormatException(
					"parameter can not be null for Base64Binary");
		}
		return new Base64Binary(Base64.decode(stringValue));
	}

	/**
	 * get byte[] from Base64Binary
	 *
	 * @return byte[] returned from this Base64Binary instance
	 */
	public byte[] getBytes() {
		return mByteList;
	}

	/**
	 * check if the specified String is a valid {@odf.datatype base64Binary} data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype base64Binary} data type
	 *         false otherwise
	 */
	public static boolean isValid(String stringValue) {
		if (stringValue == null) {
			return false;
		} else {
			return W3CSchemaType.isValid("base64Binary", stringValue);
		}
	}
}
