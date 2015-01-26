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
package org.signserver.server.cryptotokens;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Map;
import org.ejbca.util.CertTools;

/**
 * Represents an entry in the token with at minimum an alias.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TokenEntry implements Serializable {

    private final String alias;

    private Date creationDate;
    private byte[][] chain;
    private transient Certificate[] parsedChain; // Certificate might not be serializable
    private Map<String, String> info;
    
    public TokenEntry(String alias) {
        this.alias = alias;
    }

    public void setCreationDate(Date creationDate) {
        this.creationDate = creationDate;
    }

    public void setParsedChain(Certificate[] chain) throws CertificateEncodingException {
        this.parsedChain = chain;
        this.chain = new byte[chain.length][];
        for (int i = 0; i < chain.length; i++) {
            this.chain[i] = chain[i].getEncoded();
        }
    }
    
    public Certificate[] getParsedChain() throws CertificateException {
        if (this.parsedChain == null) {
            this.parsedChain = new Certificate[this.chain.length];
            int i = 0;
            for (byte[] certBytes : this.chain) {
                this.parsedChain[i] = CertTools.getCertfromByteArray(certBytes, "BC");
                i++;
            }
        }
        return this.parsedChain;
    }
    
    public byte[][] getChain() {
        return chain;
    }
    
    public void setChain(byte[][] chain) {
        if (this.chain != chain) {
            this.parsedChain = null;
        }
        this.chain = chain;
    }

    public String getAlias() {
        return alias;
    }

    public Date getCreationDate() {
        return creationDate;
    }
    
    public void setInfo(Map<String, String> info) {
        this.info = info;
    }
    
    public Map<String, String> getInfo() {
        return this.info;
    }

    @Override
    public String toString() {
        return "TokenEntry{" + "alias=" + alias + '}';
    }
    
}
