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
package org.odftoolkit.odfdom.incubator.search;

/**
 * Thrown to indicate that the navigation operation  
 * can not be processed on selections
 */
public class InvalidNavigationException extends Exception {

    private static final long serialVersionUID = -6139894252732076102L;

    /**
     * Constructs a <code>InvalidNavigateOperation</code> with the 
     * specified detail message. 
     *
     * @param   msg   the detail message.
     */
    public InvalidNavigationException(String msg) {
	super(msg);
    }
}
