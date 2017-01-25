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
 * Request data to be sent to the processSOD operation.
 *
 * @author Markus Kilås
 * @version $Id$
 * @see ClientWS#processSOD(java.lang.String, java.util.List, org.signserver.clientws.SODRequest) 
 */
public class SODRequest {
 
    private List<DataGroup> dataGroups;
    private String ldsVersion;
    private String unicodeVersion;

    public SODRequest() {
    }

    /**
     * Creates an new instance of SODRequest.
     * @param dataGroups List of datagroups or data group hashes
     * @param ldsVersion Version of LDS to use
     * @param unicodeVersion Version of Unicode to set
     */
    public SODRequest(List<DataGroup> dataGroups, String ldsVersion, String unicodeVersion) {
        this.dataGroups = dataGroups;
        this.ldsVersion = ldsVersion;
        this.unicodeVersion = unicodeVersion;
    }

    /**
     * @return List of datagroups
     */
    @XmlElement(name = "dataGroup", required = true, nillable = false) 
    public List<DataGroup> getDataGroups() {
        return dataGroups;
    }

    /**
     * @param dataGroups List of datagroups
     */
    public void setDataGroups(List<DataGroup> dataGroups) {
        this.dataGroups = dataGroups;
    }

    /**
     * @return Version of LDS
     */
    @XmlElement(name = "ldsVersion", required=false)
    public String getLdsVersion() {
        return ldsVersion;
    }

    /**
     * @param ldsVersion Version of LDS
     */
    public void setLdsVersion(String ldsVersion) {
        this.ldsVersion = ldsVersion;
    }

    /**
     * @return Version of Unicode
     */
    @XmlElement(name = "unicodeVersion", required=false)
    public String getUnicodeVersion() {
        return unicodeVersion;
    }

    /**
     * @param unicodeVersion Version of Unicode
     */
    public void setUnicodeVersion(String unicodeVersion) {
        this.unicodeVersion = unicodeVersion;
    }
    
}
