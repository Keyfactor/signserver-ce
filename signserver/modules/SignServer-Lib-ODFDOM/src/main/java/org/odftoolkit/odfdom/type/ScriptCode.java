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

/**
 * This class represents the in OpenDocument format used data type {@odf.datatype scriptCode}
 */
public class ScriptCode implements OdfDataType {

    private String mScriptCode;

    /**
     * Construct ScriptCode by the parsing the given string
     *
     * @param scriptCode
     *            The String to be parsed into ScriptCode
     * @throws IllegalArgumentException if the given argument is not a valid ScriptCode
     */
    public ScriptCode(String scriptCode) throws IllegalArgumentException {
        if ((scriptCode == null) || (!scriptCode.matches("^[A-Za-z0-9]{1,8}$"))) {
            throw new IllegalArgumentException(
                    "parameter can not be null for ScriptCode");
        }
        // validate 'token' type which is defined in W3C schema
        // http://www.w3.org/TR/xmlschema-2/#token
        if (!W3CSchemaType.isValid("token", scriptCode)) {
            throw new IllegalArgumentException(
                    "parameter is invalidate for datatype ScriptCode");
        }
        mScriptCode = scriptCode;
    }

    /**
     * Returns a String Object representing this ScriptCode's value
     *
     * @return return a string representation of the value of this ScriptCode
     *         object
     */
    @Override
    public String toString() {
        return mScriptCode;
    }

    /**
     * Returns a ScriptCode instance representing the specified String value
     *
     * @param stringValue
     *            a String value
     * @return return a ScriptCode instance representing stringValue
     * @throws IllegalArgumentException if the given argument is not a valid ScriptCode
     */
    public static ScriptCode valueOf(String stringValue)
            throws IllegalArgumentException {
        return new ScriptCode(stringValue);
    }

    /**
     * check if the specified String instance is a valid {@odf.datatype scriptCode} data type
     *
     * @param stringValue
     *            the value to be tested
     * @return true if the value of argument is valid for {@odf.datatype scriptCode} data type
     *         false otherwise
     */
    public static boolean isValid(String stringValue) {
        if (stringValue == null || !stringValue.matches("^[A-Za-z0-9]{1,8}$")) {
            return false;
        } else {
            return W3CSchemaType.isValid("token", stringValue);
        }
    }
}
