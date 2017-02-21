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
     * Get the list of data group values (data or hashes).
     *
     * @return List of datagroups
     */
    @XmlElement(name = "dataGroup", required = true, nillable = false) 
    public List<DataGroup> getDataGroups() {
        return dataGroups;
    }

    /**
     * Set the list of data group values (data or hashes).
     *
     * @param dataGroups List of datagroups
     */
    public void setDataGroups(List<DataGroup> dataGroups) {
        this.dataGroups = dataGroups;
    }

    /**
     * Get the version of the LDS.
     *
     * @return Version of LDS
     */
    @XmlElement(name = "ldsVersion", required=false)
    public String getLdsVersion() {
        return ldsVersion;
    }

    /**
     * Set the version of the LDS.
     *
     * @param ldsVersion Version of LDS
     */
    public void setLdsVersion(String ldsVersion) {
        this.ldsVersion = ldsVersion;
    }

    /**
     * Get the unicode version used.
     *
     * @return Version of Unicode
     */
    @XmlElement(name = "unicodeVersion", required=false)
    public String getUnicodeVersion() {
        return unicodeVersion;
    }

    /**
     * Set the unicode version used.
     *
     * @param unicodeVersion Version of Unicode
     */
    public void setUnicodeVersion(String unicodeVersion) {
        this.unicodeVersion = unicodeVersion;
    }
    
}
