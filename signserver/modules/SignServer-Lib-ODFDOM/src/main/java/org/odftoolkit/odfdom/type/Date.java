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

import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

/**
 * This class represents the in OpenDocument format used data type {@odf.datatype date}
 * Details of the type can be found in the <a href="http://www.w3.org/TR/xmlschema-2/#date">W3C XML Schema specification</a>.
 */
public class Date implements OdfFieldDataType, OdfDataType {

	private XMLGregorianCalendar mDate;

	/**
	 * Construct an newly Date object that represents the specified
	 * XMLGregorianCalendar value
	 *
	 * @param date
	 *            the value to be represented by the Date Object
	 * @throws IllegalArgumentException if the given argument is not a valid Date
	 *
	 */
	public Date(XMLGregorianCalendar date) throws IllegalArgumentException {
		if (date == null) {
			throw new IllegalArgumentException("parameter can not be null for date");
		}
		// validate 'date' type which is defined in W3C schema
		// see http://www.w3.org/TR/xmlschema-2/#date
		if (!W3CSchemaType.isValid("date", date.toXMLFormat())) {
			throw new IllegalArgumentException("parameter is invalidate for datatype date");
		}
		mDate = date;
	}

	/**
	 * Returns a String Object representing this Date value
	 *
	 * @return return a string representation of the value of this Date object
	 */
	@Override
	public String toString() {
		return mDate.toXMLFormat();
	}

	/**
	 * Returns a Date instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a Date instance representing stringValue
	 * @throws IllegalArgumentException If the stringValue is not a date
	 */
	public static Date valueOf(String stringValue) throws IllegalArgumentException {
		Date date = null;
		try {
			DatatypeFactory aFactory = new org.apache.xerces.jaxp.datatype.DatatypeFactoryImpl();
			date = new Date(aFactory.newXMLGregorianCalendar(stringValue));
		} catch (Throwable t) {
			throw new IllegalArgumentException(t);
		}
		return date;
	}

	/**
	 * Returns the value of this Date object as an XMLGregorianCalendar
	 *
	 * @return the XMLGregorianCalendar value of this Date object.
	 */
	public XMLGregorianCalendar getXMLGregorianCalendar() {
		return mDate;
	}

	/**
	 * check if the specified XMLGregorianCalendar instance is a valid {@odf.datatype date} data
	 * type
	 *
	 * @param date
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype date} data type false
	 *         otherwise
	 */
	public static boolean isValid(XMLGregorianCalendar date) {
		boolean isDate = false;
		if (date != null) {
			isDate = W3CSchemaType.isValid("date", date.toXMLFormat());
		}
		return isDate;
	}
}
