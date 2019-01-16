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
 * This class represents the in OpenDocument format used data type {@odf.datatype styleNameRefs}
 */
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class StyleNameRefs implements OdfDataType {

	private String mStyleNames;

	/**
	 * Construct StyleNameRefs by the parsing the given StyleName list
	 *
	 * @param styleNames The String to be parsed into StyleNameRefs
	 *
	 * @throws IllegalArgumentException if the given argument is not a valid StyleNameRefs
	 */
	public StyleNameRefs(List<StyleName> styleNames) throws IllegalArgumentException {
		if (styleNames == null) {
			throw new IllegalArgumentException("parameter can not be null for StyleNameRefs");
		}
		StringBuffer aRet = new StringBuffer();
		Iterator<StyleName> aIter = styleNames.iterator();
		while (aIter.hasNext()) {
			if (aRet.length() > 0) {
				aRet.append(' ');
			}
			String aStyleName = aIter.next().toString();
			aRet.append(aStyleName);
		}
		mStyleNames = aRet.toString();
	}

	/**
	 * Returns a String Object representing this StyleNameRefs's value
	 *
	 * @return return a string representation of the value of this StyleNameRefs
	 *         object
	 */
	@Override
	public String toString() {
		return mStyleNames;
	}

	/**
	 * Returns a StyleNameRefs instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a StyleNameRefs instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid StyleNameRefs
	 */
	public static StyleNameRefs valueOf(String stringValue) throws IllegalArgumentException {
		if (stringValue == null) {
			throw new IllegalArgumentException("parameter is invalidate for datatype StyleNameRefs");
		}

		List<StyleName> aRet = new ArrayList<StyleName>();
		if (stringValue.length() > 0) {
			String[] names = stringValue.split(" ");
			for (int i = 0; i < names.length; i++) {
				aRet.add(new StyleName(names[i]));
			}
		}
		return new StyleNameRefs(aRet);
	}

	/**
	 * Returns a list of StyleNameRef from the StyleNameRefs Object
	 *
	 * @return a list of StyleNameRef
	 */
	public List<StyleName> getStyleNameRefList() {
		List<StyleName> aRet = new ArrayList<StyleName>();
		if (mStyleNames.length() > 0) {
			String[] names = mStyleNames.split(" ");
			for (int i = 0; i < names.length; i++) {
				aRet.add(new StyleName(names[i]));
			}
		}
		return aRet;
	}

	/**
	 * check if the specified String instance is a valid {@odf.datatype styleNameRefs} data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype styleNameRefs} data
	 *         type false otherwise
	 */
	public static boolean isValid(String stringValue) {
		if (stringValue == null) {
			return false;
		}
		if (stringValue.length() == 0) {
			return true;
		}

		String[] names = stringValue.split(" ");
		for (int i = 0; i < names.length; i++) {
			if (!StyleNameRef.isValid(names[i])) {
				return false;
			}
		}
		return true;
	}
}
