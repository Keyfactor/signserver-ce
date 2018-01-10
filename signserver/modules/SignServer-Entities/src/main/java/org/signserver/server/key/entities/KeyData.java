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
    private String keyAlias;

    @Column(length = 255)
    private String wrappingKeyAlias;

    private long wrappingCipher;
    
    @Lob
    @Column(length = 1048576)
    private String keyData;
    
    @Lob
    @Column(length = 1048576)
    private String certData;

    public String getKeyAlias() {
        return keyAlias;
    }

    public void setKeyAlias(String keyAlias) {
        this.keyAlias = keyAlias;
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
    
    /**
     * @return the wrappingKeyAlias
     */
    public String getWrappingKeyAlias() {
        return wrappingKeyAlias;
    }

    /**
     * @param wrappingKeyAlias the wrappingKeyAlias to set
     */
    public void setWrappingKeyAlias(String wrappingKeyAlias) {
        this.wrappingKeyAlias = wrappingKeyAlias;
    }

    /**
     * @return the wrappingCipher
     */
    public long getWrappingCipher() {
        return wrappingCipher;
    }

    /**
     * @param wrappingCipher the wrappingCipher to set
     */
    public void setWrappingCipher(long wrappingCipher) {
        this.wrappingCipher = wrappingCipher;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 37 * hash + (this.keyAlias != null ? this.keyAlias.hashCode() : 0);
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
        if ((this.keyAlias == null) ? (other.keyAlias != null) : !this.keyAlias.equals(other.keyAlias)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "KeyData{" + "keyAlias=" + keyAlias + '}';
    }

}
