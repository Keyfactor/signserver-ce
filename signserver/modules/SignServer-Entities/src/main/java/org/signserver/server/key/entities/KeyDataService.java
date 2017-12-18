/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.key.entities;

import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.Query;

/**
 *
 * @author markus
 */
public class KeyDataService {
    
    private EntityManager em;

    public KeyDataService(EntityManager em) {
        this.em = em;
    }

    public void create(String keyAlias, String keyData, String certData, String wrappingKeyAlias, long wrappingCipher) throws AliasAlreadyExistsException {
        KeyData data = em.find(KeyData.class, keyAlias);
        if (data == null) {
            data = new KeyData();
            data.setKeyAlias(keyAlias);
            data.setKeyData(keyData);
            data.setCertData(certData);
            data.setWrappingKeyAlias(wrappingKeyAlias);
            data.setWrappingCipher(wrappingCipher);
            em.persist(data);
        } else {
            throw new AliasAlreadyExistsException(keyAlias);
        }
    }
    
    public List<KeyData> findAll() {
        Query query = em.createQuery("SELECT e from KeyData e");

        return (List<KeyData>) query.getResultList();
    }
    
    public KeyData find(String keyAlias) {
        return em.find(KeyData.class, keyAlias);
    }
    
    public boolean remove(String keyAlias) {
        boolean retval = false;
        KeyData data = find(keyAlias);
        if (data != null) {
            em.remove(data);
            retval = true;
        }
        return retval;
    }
    
    public void update(KeyData keyData) {
        em.persist(keyData);
    }

}
