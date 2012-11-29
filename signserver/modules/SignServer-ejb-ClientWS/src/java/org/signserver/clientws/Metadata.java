/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.clientws;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlValue;

/**
 * Representation of additional request or response metadata in a key value 
 * pair.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class Metadata {
    private String name;
    private String value;

    public Metadata() {
    }

    /**
     * Create a new instance of Metdata.
     * @param name Name of the key
     * @param value The value
     */
    public Metadata(String name, String value) {
        this.name = name;
        this.value = value;
    }

    /**
     * @return Name of the key
     */
    @XmlAttribute(required=true)
    public String getName() {
        return name;
    }

    /**
     * @param name Name of the key
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * @return The value
     */
    @XmlValue
    public String getValue() {
        return value;
    }

    /**
     * @param value The value
     */
    public void setValue(String value) {
        this.value = value;
    }
    
}
