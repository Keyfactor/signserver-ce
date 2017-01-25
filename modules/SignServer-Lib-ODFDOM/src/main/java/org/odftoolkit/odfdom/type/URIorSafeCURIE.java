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

import java.net.URI;

/**
 * This class represents the in OpenDocument format used data type {@odf.datatype URIorSafeCURIE}
 *  This value type stores either an anyURI or a SafeCURIE
 */
public class URIorSafeCURIE implements OdfDataType {

	private String mURIorSafeCURIE;
	private Object mValue;

	/**
	 * Construct URIorSafeCURIE without the initialized value
	 */
	public URIorSafeCURIE() {
		mValue = null;
	}

	/**
	 * Copy Construct URIorSafeCURIE with the same value of val
	 *
	 * @param val
	 *            the copied URIorSafeCURIE object
	 * @throws IllegalArgumentException if the given argument is not a valid URIorSaveCURIE
	 */
	public URIorSafeCURIE(URIorSafeCURIE val) {
		if (val == null) {
			throw new IllegalArgumentException("parameter can not be null for URIorSafeCURIE");
		}

		if (val.isSafeCURIE()) {
			mURIorSafeCURIE = val.getSafeCURIE();
		} else {
			mURIorSafeCURIE = (new AnyURI(val.getAnyURI())).toString();
		}
	}

	/**
	 * set uri value for URIorSafeCURIE Object
	 *
	 * @param uri
	 *            the anyURI value which is set to URIorSafeCURIE Object
	 */
	public void setAnyURI(URI uri) {
		mValue = new AnyURI(uri);
	}

	/**
	 * set String value for URIorSafeCURIE Object
	 *
	 * @param curie
	 *            the SafeCURIE value which is set to URIorSafeCURIE Object
	 */
	public void setSafeCURIE(String curie) {
		mValue = new SafeCURIE(curie);
	}

	/**
	 * get the internal value type of URIorSafeCURIE Object
	 *
	 * @return true if the internal value type is anyURI false if the internal
	 *         value type is SafeCURIE
	 */
	public boolean isSafeCURIE() {
		return (mValue != null) && mValue instanceof SafeCURIE;
	}

	/**
	 * get the anyURI value of this URIorSafeCURIE Object
	 *
	 * @return the anyURI value of this URIorSafeCURIE Object
	 */
	public URI getAnyURI() {
		if (isSafeCURIE()) {
			throw new IllegalArgumentException("I do not have a AnyURI value");
		} else if (mValue != null) {
			return ((AnyURI) mValue).getURI();
		} else {
			return null;
		}
	}

	/**
	 * get the SafeCURIE value of this URIorSafeCURIE Object
	 *
	 * @return the SafeCURIE value of this URIorSafeCURIE Object
	 */
	public String getSafeCURIE() {
		if (isSafeCURIE()) {
			return ((SafeCURIE) mValue).toString();
		} else {
			throw new IllegalArgumentException(
					"I do not have a SafeCURIE value");
		}
	}

	/**
	 * Returns a String Object representing this URIorSafeCURIE's value
	 *
	 * @return return a string representation of the value of this
	 *         URIorSafeCURIE object
	 */
	@Override
	public String toString() {
		return mURIorSafeCURIE;
	}

	/**
	 * Returns an URIorSafeCURIE instance representing the specified String
	 * value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return an URIorSafeCURIE instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid URIorSaveCURIE
	 */
	public static URIorSafeCURIE valueOf(String stringValue)
			throws IllegalArgumentException {
		if (stringValue == null) {
			throw new IllegalArgumentException("parameter can not be null for URIorSafeCURIE");
		}
		URIorSafeCURIE aRet = new URIorSafeCURIE();
		if ((stringValue.matches("^\\[(([\\i-[:]][\\c-[:]]*)?:)?.+\\]$")) && (stringValue.length() >= 3)) {
			aRet.setSafeCURIE(stringValue);
		} else {
			AnyURI aAnyURI = AnyURI.valueOf(stringValue);
			if (aAnyURI != null) {
				aRet.setAnyURI(aAnyURI.getURI());
			} else {
				throw new IllegalArgumentException("parameter is invalidate for datatype URIorSafeCURIE");
			}
		}
		return aRet;
	}

	/**
	 * check if the specified XMLGregorianCalendar {@odf.datatype URIorSafeCURIE} is a valid
	 * URIorSafeCURIE data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype URIorSafeCURIE} data
	 *         type false otherwise
	 */
	public static boolean isValid(String stringValue) {
		if (SafeCURIE.isValid(stringValue)) {
			return true;
		} else if (AnyURI.valueOf(stringValue) != null) {
			return true;
		} else {
			return false;
		}
	}
}
