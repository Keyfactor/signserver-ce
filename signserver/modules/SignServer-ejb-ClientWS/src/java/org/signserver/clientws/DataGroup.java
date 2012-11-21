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
 * Representation of an LDS data group containing either data or an hash of data.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class DataGroup {
    private int id;
    private byte[] value;

    public DataGroup() {
    }
    
    public DataGroup(int id, byte[] value) {
        this.id = id;
        this.value = value;
    }

    @XmlAttribute(name="id", required=true)
    public int getId() {
        return id;
    }

    @XmlValue
    public byte[] getValue() {
        return value;
    }

    public void setId(int id) {
        this.id = id;
    }

    public void setValue(byte[] value) {
        this.value = value;
    }
    
}
