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

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

/**
 * This class represents the in OpenDocument format used data type {@odf.datatype time}
 */
public class Time implements OdfDataType {

	private XMLGregorianCalendar mTime;

	/**
	 * Construct an newly Time object that represents the specified
	 * XMLGregorianCalendar value
	 *
	 * @param time
	 *            the value to be represented by the Time Object
	 * @throws IllegalArgumentException if the given argument is not a valid Time
	 */
	public Time(XMLGregorianCalendar time) throws IllegalArgumentException {
		if (time == null) {
			throw new IllegalArgumentException(
					"parameter can not be null for Time");
		}

		// validate 'time' type which is defined in W3C schema
		// http://www.w3.org/TR/xmlschema-2/#time
		if (!W3CSchemaType.isValid("time", time.toXMLFormat())) {
			throw new IllegalArgumentException(
					"parameter is invalidate for datatype Time");
		}
		mTime = time;
	}

	/**
	 * Returns a String Object representing this Time value
	 *
	 * @return return a string representation of the value of this Time object
	 */
	@Override
	public String toString() {
		return mTime.toXMLFormat();
	}

	/**
	 * Returns a Time instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a Time instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid Time
	 */
	public static Time valueOf(String stringValue) throws IllegalArgumentException {
		try {
			DatatypeFactory aFactory = new org.apache.xerces.jaxp.datatype.DatatypeFactoryImpl();
			return new Time(aFactory.newXMLGregorianCalendar(stringValue));
		} catch (IllegalArgumentException ex) {
			Logger.getLogger(Time.class.getName()).log(Level.SEVERE,
					"parameter is invalidate for datatype Time", ex);
			throw new IllegalArgumentException(
					"parameter is invalidate for datatype Time");
		}
	}

	/**
	 * Returns the value of this Time object as an XMLGregorianCalendar
	 *
	 * @return the XMLGregorianCalendar value of this Time object.
	 */
	public XMLGregorianCalendar getXMLGregorianCalendar() {
		return mTime;
	}

	/**
	 * check if the specified XMLGregorianCalendar instance is a valid {@odf.datatype time} data
	 * type
	 *
	 * @param time
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype time} data type false
	 *         otherwise
	 */
	public static boolean isValid(XMLGregorianCalendar time) {
		if (time == null) {
			return false;
		} else {
			return W3CSchemaType.isValid("time", time.toXMLFormat());
		}
	}
}
