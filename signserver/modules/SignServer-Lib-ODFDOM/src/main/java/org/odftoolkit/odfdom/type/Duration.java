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

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;

/**
 * This class represents the in OpenDocument format used data type {@odf.datatype duration}
 */
public class Duration implements OdfFieldDataType, OdfDataType {

	private javax.xml.datatype.Duration mDurationType;

	/**
	 * Construct DurationType by the parsing the given string
	 *
	 * @param duration	The String to be parsed into DurationType
	 * @throws IllegalArgumentException if the given argument is not a valid Duration
	 */
	public Duration(javax.xml.datatype.Duration duration) throws IllegalArgumentException {
		if (duration == null) {
			throw new IllegalArgumentException("parameter can not be null for duration");
		}

		// validate 'duration' type which is defined in W3C schema
		// http://www.w3.org/TR/xmlschema-2/#duration
		if (!W3CSchemaType.isValid("duration", duration.toString())) {
			throw new IllegalArgumentException(
					"parameter is invalidate for datatype duration");
		}
		mDurationType = duration;
	}

	/**
	 * Returns a String Object representing this DurationType's value
	 *
	 * @return return a string representation of the value of this DurationType
	 *         object
	 */
	@Override
	public String toString() {
		return mDurationType.toString();
	}

	/**
	 * Returns a DurationType instance representing the specified String value
	 *
	 * @param stringValue  a String value
	 *
	 * @return return a DurationType instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid Duration
	 */
	public static Duration valueOf(String stringValue)
			throws IllegalArgumentException {
		if (stringValue == null) {
			throw new IllegalArgumentException(
					"parameter can not be null for Duration");
		}

		try {
			DatatypeFactory aFactory = DatatypeFactory.newInstance();
			return new Duration(aFactory.newDuration(stringValue));
		} catch (DatatypeConfigurationException ex1) {
			Logger.getLogger(Duration.class.getName()).log(Level.SEVERE,
					"DatatypeFactory can not be instanced", ex1);
			return null;
		} catch (IllegalArgumentException ex2) {
			Logger.getLogger(Duration.class.getName()).log(Level.SEVERE,
					"parameter is invalidate for datatype Duration", ex2);
			throw new IllegalArgumentException(
					"parameter is invalidate for datatype Duration");
		}
	}

	/**
	 * Returns the value of this DurationType object as an Duration
	 *
	 * @return the Duration value of this DurationType object.
	 */
	public javax.xml.datatype.Duration getValue() {
		return mDurationType;
	}

	/**
	 * check if the specified Duration instance is a valid {@odf.datatype duration} data type
	 *
	 * @param duration  the value to be tested
	 *
	 * @return true if the value of argument is valid for {@odf.datatype duration} data type
	 *         false otherwise
	 */
	public static boolean isValid(javax.xml.datatype.Duration duration) {
		boolean isDuration = false;
		if (duration != null) {
			isDuration = W3CSchemaType.isValid("duration", duration.toString());
		}
		return isDuration;
	}
}
