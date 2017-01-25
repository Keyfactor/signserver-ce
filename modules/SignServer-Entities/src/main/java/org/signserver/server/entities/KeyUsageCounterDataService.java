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
package org.signserver.server.entities;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import org.apache.log4j.Logger;

/**
 * Entity Service class that acts as migration layer for
 * the old Home Interface for the Worker Config Entity Bean
 * 
 * Contains about the same methods as the EJB 2 entity beans home interface.
 *
 * @version $Id$
 */
public class KeyUsageCounterDataService implements IKeyUsageCounterDataService {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(KeyUsageCounterDataService.class);
    
    private EntityManager em;

    public KeyUsageCounterDataService(EntityManager em) {
        this.em = em;
    }

    @Override
    public void create(final String keyHash) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating keyusagecounter " + keyHash);
        }
        KeyUsageCounter counter = new KeyUsageCounter(keyHash, 0L);
        em.persist(counter);
    }
    
    @Override
    public KeyUsageCounter getCounter(final String keyHash) {
        return em.find(KeyUsageCounter.class, keyHash);
    }

    @Override
    public boolean incrementIfWithinLimit(String keyHash, long limit) {
        final Query updateQuery;
        if (limit < 0) {
            updateQuery = em.createQuery("UPDATE KeyUsageCounter w SET w.counter = w.counter + 1 WHERE w.keyHash = :keyhash");
        } else {
            updateQuery = em.createQuery("UPDATE KeyUsageCounter w SET w.counter = w.counter + 1 WHERE w.keyHash = :keyhash AND w.counter < :limit");
            updateQuery.setParameter("limit", limit);
        }
        updateQuery.setParameter("keyhash", keyHash);

        return updateQuery.executeUpdate() > 0;
    }

    @Override
    public boolean isWithinLimit(String keyHash, long keyUsageLimit) {
        final Query selectQuery;
        selectQuery = em.createQuery("SELECT COUNT(w) FROM KeyUsageCounter w WHERE w.keyHash = :keyhash AND w.counter < :limit");
        selectQuery.setParameter("limit", keyUsageLimit);
        selectQuery.setParameter("keyhash", keyHash);
        return selectQuery.getResultList().size() > 0;
    }

}
