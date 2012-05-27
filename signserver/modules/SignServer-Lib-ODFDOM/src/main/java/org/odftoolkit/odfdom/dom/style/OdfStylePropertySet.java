/************************************************************************
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
 * 
 * Copyright 2008 Sun Microsystems, Inc. All rights reserved.
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

package org.odftoolkit.odfdom.dom.style;

import java.util.Map;

import org.odftoolkit.odfdom.dom.style.props.OdfStyleProperty;

import java.util.Set;

/**
 *
 */
public interface OdfStylePropertySet
{
    /** checks if this styleable element or style has this property directly set.
     * 
     * @param property is the property to check.
     * @return true if this property is directly set at this instance or false if not.
     */
    public boolean hasProperty( OdfStyleProperty property );

    /** returns the given property from this styleable element or style.
     * If it is not directly set, the value of this property from a parent style
     * will be returned.
     * 
     * @param property is the property which value will be returned.
     * @return the value of this property or null if it is not available in this
     * set or this parents sets.
     */
    public String getProperty( OdfStyleProperty property );

    /** removes the given property from this set
     * 
     * @param property is the property to be removed
     */
    public void removeProperty( OdfStyleProperty property );
    
    /** sets a single style property for this element.
     * 
     * @param property is the property that you want to set.
     * @param value is the value the property is set to.
     */
    public void setProperty( OdfStyleProperty property, String value );

    /** set more than one property at once.
     * 
     * @param properties is a map of properties with values that should be set.
     */
    public void setProperties( Map< OdfStyleProperty, String > properties );
    
    /** gets more than one property at once
     * 
     * @param properties is a set of all properties that should be returned.
     * @return a map with all asked properties and theire value, if available.
     */
    public Map< OdfStyleProperty, String > getProperties( Set< OdfStyleProperty > properties );
                                    
    /** 
     * @return a set with all properties which are specified in the strict odf format.
     */
    public Set< OdfStyleProperty > getStrictProperties();     
}
