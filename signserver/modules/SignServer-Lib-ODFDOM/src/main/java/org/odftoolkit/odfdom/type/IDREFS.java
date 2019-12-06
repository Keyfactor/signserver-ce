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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * This class represents the in OpenDocument format used data type {@odf.datatype IDREFS}
 */
public class IDREFS implements OdfDataType {

	private String mIdRefs;

	/**
	 * Construct IDREFS by the parsing the given IDREF list
	 *
	 * @param idRefList
	 *            The String to be parsed into IDREFS
	 * @throws IllegalArgumentException if the given argument is not a valid IDREFS
	 */
	public IDREFS(List<IDREF> idRefList) throws IllegalArgumentException {
		if ((idRefList == null) || (idRefList.size() == 0)) {
			throw new IllegalArgumentException(
					"parameter can not be null for IDREFS");
		}
		StringBuffer aRet = new StringBuffer();
		Iterator<IDREF> aIter = idRefList.iterator();
		while (aIter.hasNext()) {
			if (aRet.length() > 0) {
				aRet.append(' ');
			}
			String styleName = aIter.next().toString();
			aRet.append(styleName);
		}
		mIdRefs = aRet.toString();
	}

	/**
	 * Returns a String Object representing this IDREFS's value
	 *
	 * @return return a string representation of the value of this IDREFS object
	 */
	@Override
	public String toString() {
		return mIdRefs;
	}

	/**
	 * Returns an IDREFS instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return an IDREFS instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid IDREFS
	 */
	public static IDREFS valueOf(String stringValue)
			throws IllegalArgumentException {
		if ((stringValue == null) || (stringValue.length() == 0)) {
			throw new IllegalArgumentException(
					"parameter is invalidate for datatype IDREFS");
		}

		List<IDREF> aRet = new ArrayList<IDREF>();
		String[] names = stringValue.split(" ");
		for (int i = 0; i < names.length; i++) {
			aRet.add(new IDREF(names[i]));
		}
		return new IDREFS(aRet);
	}

	/**
	 * Returns a list of IDREF from the IDREFS Object
	 *
	 * @return a list of IDREF
	 */
	public List<IDREF> getIDREFList() {
		List<IDREF> aRet = new ArrayList<IDREF>();
		String[] names = mIdRefs.split(" ");
		for (int i = 0; i < names.length; i++) {
			aRet.add(new IDREF(names[i]));
		}
		return aRet;
	}

	/**
	 * check if the specified String instance is a valid {@odf.datatype IDREFS} data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype IDREFS} data type false
	 *         otherwise
	 */
	public static boolean isValid(String stringValue) {
		if (stringValue == null) {
			return false;
		}
		if (stringValue.length() == 0) {
			return false;
		}

		String[] names = stringValue.split(" ");
		for (int i = 0; i < names.length; i++) {
			if (!IDREF.isValid(names[i])) {
				return false;
			}
		}
		return true;
	}
}
