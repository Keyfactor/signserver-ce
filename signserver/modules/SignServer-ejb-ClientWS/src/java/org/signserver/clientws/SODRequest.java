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

import java.util.List;
import javax.xml.bind.annotation.XmlElement;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SODRequest {
 
    private List<DataGroup> dataGroups;
    private String ldsVersion;
    private String unicodeVersion;

    public SODRequest() {
    }

    public SODRequest(List<DataGroup> dataGroups, String ldsVersion, String unicodeVersion) {
        this.dataGroups = dataGroups;
        this.ldsVersion = ldsVersion;
        this.unicodeVersion = unicodeVersion;
    }

    @XmlElement(name = "dataGroup", required = true, nillable = false) 
    public List<DataGroup> getDataGroups() {
        return dataGroups;
    }

    public void setDataGroups(List<DataGroup> dataGroups) {
        this.dataGroups = dataGroups;
    }

    @XmlElement(name = "ldsVersion", required=false)
    public String getLdsVersion() {
        return ldsVersion;
    }

    public void setLdsVersion(String ldsVersion) {
        this.ldsVersion = ldsVersion;
    }

    @XmlElement(name = "unicodeVersion", required=false)
    public String getUnicodeVersion() {
        return unicodeVersion;
    }

    public void setUnicodeVersion(String unicodeVersion) {
        this.unicodeVersion = unicodeVersion;
    }
    
}
