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
import org.apache.xerces.impl.dv.InvalidDatatypeValueException;
import org.apache.xerces.impl.dv.SchemaDVFactory;
import org.apache.xerces.impl.dv.ValidatedInfo;
import org.apache.xerces.impl.dv.XSSimpleType;
import org.apache.xerces.impl.validation.ValidationState;

/** This class validates string to be valid W3C schema data types.
In general it takes advantage of already existing underlying parser functionality and encapsulates it */
class W3CSchemaType {
	// validate the content by the dataType which is defined in XML schema

	private static final Logger LOG = Logger.getLogger(W3CSchemaType.class.getName());

	static boolean isValid(String dataType, String content) {
		boolean isValid = false;
		try {
			// SchemaDVFactory / Enumeration Dataype
			XSSimpleType simpleType = SchemaDVFactory.getInstance().getBuiltInType(dataType);
			if (simpleType != null) {
				simpleType.validate(content, new ValidationState(), new ValidatedInfo());
				isValid = true; //Xerces docu is a little weak, we assume it works this way
			} else {
				throw new IllegalArgumentException("Datatype " + dataType + " does not exist!");
			}
		} catch (InvalidDatatypeValueException e) {
			isValid = false;
			LOG.log(Level.FINE, content + "is not of datatype " + dataType + "!", e);
		}
		return isValid;
	}

	private W3CSchemaType() {
	}
}
