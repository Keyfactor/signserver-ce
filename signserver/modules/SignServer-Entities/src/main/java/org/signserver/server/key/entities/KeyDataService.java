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
package org.signserver.server.key.entities;

import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.Query;

/**
 * Service for interacting with the key data entities.
 *
 * @author Markus Kilås
 * @version $Id$
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
