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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * This class represents the in OpenDocument format used data type {@odf.datatype CURIEs}
 */
public class CURIEs implements OdfDataType {

	private String mCURIEs;

	/**
	 * Construct CURIEs by the parsing the given string
	 *
	 * @param curies
	 *            The String to be parsed into CURIEs
	 * @throws IllegalArgumentException if the given argument is not a valid CURIEs
	 */
	public CURIEs(List<CURIE> curies) throws IllegalArgumentException {
		if ((curies == null) || (curies.size() == 0)) {
			throw new IllegalArgumentException("parameter can not be null for CURIEs");
		}
		StringBuffer aRet = new StringBuffer();
		Iterator<CURIE> aIter = curies.iterator();
		while (aIter.hasNext()) {
			if (aRet.length() > 0) {
				aRet.append(' ');
			}
			String aCurie = aIter.next().toString();
			aRet.append(aCurie);
		}
		mCURIEs = aRet.toString();
	}

	/**
	 * Returns a space separated String Object representing this CURIEs's value
	 *
	 * @return return a string representation of the value of this CURIEs object
	 */
	@Override
	public String toString() {
		return mCURIEs;
	}

	/**
	 * Returns a CURIEs instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a CURIEs instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid CURIEs
	 */
	public static CURIEs valueOf(String stringValue)
			throws IllegalArgumentException {
		if ((stringValue == null) || (stringValue.length() == 0)) {
			throw new IllegalArgumentException(
					"parameter is invalidate for datatype CURIEs");
		}

		List<CURIE> aRet = new ArrayList<CURIE>();
		String[] names = stringValue.split(" ");
		for (int i = 0; i < names.length; i++) {
			aRet.add(new CURIE(names[i]));
		}
		return new CURIEs(aRet);
	}

	/**
	 * Returns a list of CURIE from the CURIEs Object
	 *
	 * @return a list of CURIE
	 */
	public List<CURIE> getCURIEList() {
		List<CURIE> aRet = new ArrayList<CURIE>();
		String[] names = mCURIEs.split(" ");
		for (int i = 0; i < names.length; i++) {
			aRet.add(new CURIE(names[i]));
		}
		return aRet;
	}

	/**
	 * check if the specified String is a valid {@odf.datatype CURIEs} data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype CURIEs} data type false
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
			if (!CURIE.isValid(names[i])) {
				return false;
			}
		}
		return true;
	}
}
