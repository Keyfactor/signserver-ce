/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.cryptotokens;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.Date;

/**
 *
 * @author user
 */
public class TokenEntry implements Serializable {

    private final String alias;
    private Date creationDate;
    private Certificate[] chain;
    
    public TokenEntry(String alias) {
        this.alias = alias;
    }

    public void setCreationDate(Date creationDate) {
        this.creationDate = creationDate;
    }

    public void setCertificateChain(Certificate[] chain) {
        this.chain = chain;
    }

    public String getAlias() {
        return alias;
    }

    public Date getCreationDate() {
        return creationDate;
    }

    public Certificate[] getChain() {
        return chain;
    }

    @Override
    public String toString() {
        return "TokenEntry{" + "alias=" + alias + ", creationDate=" + creationDate + ", chain=" + chain + '}';
    }
    
}
