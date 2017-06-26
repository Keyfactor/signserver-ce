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
 * This class represents the in OpenDocument format used data type {@odf.datatype dateTime}
 */
public class DateTime implements OdfDataType {

	private XMLGregorianCalendar mDateTime;

	/**
	 * Construct an newly DateTime object that represents the specified
	 * XMLGregorianCalendar value
	 *
	 * @param dateTime
	 *            the value to be represented by the DateTime Object
	 * @throws IllegalArgumentException if the given argument is not a valid DateTime
	 */
	public DateTime(XMLGregorianCalendar dateTime) throws IllegalArgumentException {
		if (dateTime == null) {
			throw new IllegalArgumentException("parameter can not be null for DateTime");
		}
		// validate 'dateTime' type which is defined in W3C schema
		// http://www.w3.org/TR/xmlschema-2/#dateTime
		if (!W3CSchemaType.isValid("dateTime", dateTime.toXMLFormat())) {
			throw new IllegalArgumentException("parameter is invalidate for datatype dateTime");
		}
		mDateTime = dateTime;
	}

	/**
	 * Returns a String Object representing this DateTime value
	 *
	 * @return return a string representation of the value of this DateTime
	 *         object
	 */
	@Override
	public String toString() {
		return mDateTime.toXMLFormat();
	}

	/**
	 * Returns a DateTime instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a DateTime instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid DateTime
	 */
	public static DateTime valueOf(String stringValue) throws IllegalArgumentException {
		try {
			DatatypeFactory aFactory = new org.apache.xerces.jaxp.datatype.DatatypeFactoryImpl();
			return new DateTime(aFactory.newXMLGregorianCalendar(stringValue));
		} catch (IllegalArgumentException ex) {
			Logger.getLogger(DateTime.class.getName()).log(Level.SEVERE,
					"parameter is invalidate for datatype DateTime", ex);
			throw new IllegalArgumentException(
					"parameter is invalidate for datatype DateTime");
		}
	}

	/**
	 * Returns the value of this DateTime object as an XMLGregorianCalendar
	 *
	 * @return the XMLGregorianCalendar value of this DateTime object.
	 */
	public XMLGregorianCalendar getXMLGregorianCalendar() {
		return mDateTime;
	}

	/**
	 * check if the specified XMLGregorianCalendar instance is a valid {@odf.datatype dateTime} data
	 * type
	 *
	 * @param date
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype dateTime} data type false
	 *         otherwise
	 */
	public static boolean isValid(XMLGregorianCalendar date) {
		if (date == null) {
			return false;
		} else {
			return W3CSchemaType.isValid("dateTime", date.toString());
		}
	}
}
