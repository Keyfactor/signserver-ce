/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.key.entities;

import java.io.Serializable;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Lob;

/**
 *
 * @author markus
 */
@Entity
public class KeyData implements Serializable {
    private static final long serialVersionUID = 1L;

    @Id
    @Column(length = 255)
    private String alias;

    @Lob
    @Column(length = 1048576)
    private String keyData;
    
    @Lob
    @Column(length = 1048576)
    private String certData;

    public String getKeyAlias() {
        return alias;
    }

    public void setKeyAlias(String keyAlias) {
        this.alias = keyAlias;
    }

    public String getKeyData() {
        return keyData;
    }

    public void setKeyData(String keyData) {
        this.keyData = keyData;
    }

    public String getCertData() {
        return certData;
    }

    public void setCertData(String certData) {
        this.certData = certData;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 37 * hash + (this.alias != null ? this.alias.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final KeyData other = (KeyData) obj;
        if ((this.alias == null) ? (other.alias != null) : !this.alias.equals(other.alias)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "KeyData{" + "keyAlias=" + alias + '}';
    }

}
