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
package org.odftoolkit.odfdom.dom.style.props;

import java.util.Iterator;
import java.util.TreeSet;

import org.odftoolkit.odfdom.OdfName;

/**
 * Class to represent a odf style attribut. Each instance has a name and belongs
 * to an ODF style-properties element. 
 */
public class OdfStyleProperty implements Comparable<OdfStyleProperty> {

    private OdfStylePropertiesSet m_propSet;
    private OdfName m_name;

    private OdfStyleProperty(OdfStylePropertiesSet propSet, OdfName name) {
        m_propSet = propSet;
        m_name = name;
    }
    private static TreeSet<OdfStyleProperty> m_styleProperties = new TreeSet<OdfStyleProperty>();

    /**
     * Looks if an OdfStyleProperty is already listed in the static sytleProperties set,
     * otherwise creates a new one.
     * @param propSet an OdfStylePropertiesSet member
     * @param name
     * @return new created or existing OdfStylePorperty
     */
     public static OdfStyleProperty get(OdfStylePropertiesSet propSet, OdfName name) {
        OdfStyleProperty temp = new OdfStyleProperty(propSet, name);
        //Replacement for (JDK1.6)
        //OdfStyleProperty result = m_styleProperties.floor(temp);

        Iterator<OdfStyleProperty> iter = m_styleProperties.iterator();
        OdfStyleProperty result = null;

        //check if key exists 
        if (!m_styleProperties.contains(temp)) {
            m_styleProperties.add(temp);
            return temp;
        }
        while (iter.hasNext()) {
            result = iter.next();
            if (result.equals(temp)) {
                return result;
            }
        }

        m_styleProperties.add(temp);
        return temp;
        
    }

    /**
     * 
     * @return an OdfStylePropertiesSet member 
     */
    public OdfStylePropertiesSet getPropertySet() {
        return m_propSet;
    }

    /**
     * 
     * @return name of OdfStyleProperty instance
     */
    public OdfName getName() {
        return m_name;
    }

    /** 
     * @inheritDoc
     */
    @Override
    public String toString() {
        return m_name.getQName();
    }

    public OdfStyleProperty copy() {
        OdfStyleProperty clone = new OdfStyleProperty(m_propSet, m_name);
        return clone;
    }

    /** 
     * @inheritDoc
     */
    @Override
    public int hashCode() {
        int hash = 3;
        hash = 83 * hash + (this.m_propSet != null ? this.m_propSet.hashCode() : 0);
        hash = 83 * hash + (this.m_name != null ? this.m_name.hashCode() : 0);
        return hash;
    }

    /** 
     * @inheritDoc
     */
    @Override
    public boolean equals(Object o) {
    	if (o instanceof OdfStyleProperty) {
    		OdfStyleProperty sp = (OdfStyleProperty) o;
    		return compareTo(sp) == 0;
    	}
        return false;
    }

    public int compareTo(OdfStyleProperty o) {
        if (!(o instanceof OdfStyleProperty)) {
            return -1;
        }
        OdfStyleProperty prop = o;
        int c = 0;
        if ((c = m_propSet.compareTo(prop.m_propSet)) != 0) {
            return c;
        }
        if ((c = m_name.compareTo(prop.m_name)) != 0) {
            return c;
        }
        // all is equal...
        return 0;
    }
}
