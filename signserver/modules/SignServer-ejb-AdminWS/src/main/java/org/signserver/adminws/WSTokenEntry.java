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
package org.signserver.adminws;

import java.util.Date;
import java.util.Map;
import javax.xml.bind.annotation.XmlType;
import org.signserver.server.cryptotokens.TokenEntry;

/**
 * WS version of TokenEntry.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@XmlType(name = "tokenEntry")
public class WSTokenEntry {
    private String alias;
    private String type;
    private byte[][] chain;
    private byte[] trustedCertificate;
    private Date creationDate;
    private Map<String, String> info;
    
    /**
     * Converts a TokenEntry to a WSTokenEntry.
     * @param src the TokenEntry
     * @return the WSTokenEntry
     */
    public static WSTokenEntry fromTokenEntry(final TokenEntry src) {
        return new WSTokenEntry(src.getAlias(), src.getType(), src.getChain(), src.getTrustedCertificate(), src.getCreationDate(), src.getInfo());
    }
    
    /** Default no-arg constructor. */
    public WSTokenEntry() {
    }

    public WSTokenEntry(String alias, String type, byte[][] chain, byte[] trustedCertificate, Date creationDate, Map<String, String> info) {
        this.alias = alias;
        this.type = type;
        this.chain = chain;
        this.trustedCertificate = trustedCertificate;
        this.creationDate = creationDate;
        this.info = info;
    }
    
    public WSTokenEntry(String alias, String type) {
        this.alias = alias;
        this.type = type;
    }
    
    public String getType() {
        return this.type;
    }

    public void setCreationDate(Date creationDate) {
        this.creationDate = creationDate;
    }
    
    public byte[][] getChain() {
        return chain;
    }
    
    public void setChain(byte[][] chain) {
        this.chain = chain;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Date getCreationDate() {
        return creationDate;
    }

    public byte[] getTrustedCertificate() {
        return trustedCertificate;
    }

    public void setTrustedCertificate(byte[] trustedCertificate) {
        this.trustedCertificate = trustedCertificate;
    }
    
    public void setInfo(Map<String, String> info) {
        this.info = info;
    }
    
    public Map<String, String> getInfo() {
        return this.info;
    }
}
