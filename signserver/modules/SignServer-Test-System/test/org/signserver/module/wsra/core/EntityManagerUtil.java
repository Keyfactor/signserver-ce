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
 
package org.signserver.module.wsra.core;

import java.lang.reflect.Constructor;
import java.util.Map;
import java.util.Properties;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContextType;
import javax.persistence.spi.PersistenceUnitTransactionType;
import org.apache.log4j.Logger;
import org.hibernate.SessionFactory;
import org.hibernate.ejb.EntityManagerImpl;

/**
 * TODO: Document me!
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class EntityManagerUtil {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(EntityManagerImpl.class);

    /**
     * Creates EntityManagerImpl by reflection in order to support both old and
     * newer versions of the library.
     * @param sf
     * @param persistenceContextType
     * @param persistenceUnitTransactionType
     * @param TRANSACTION
     * @param RESOURCE_LOCAL
     * @return
     */
    public static EntityManager createEntityManager(SessionFactory sf, PersistenceContextType persistenceContextType, PersistenceUnitTransactionType persistenceUnitTransactionType, boolean TRANSACTION, Properties RESOURCE_LOCAL) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("EntityManager Implementation version: "
                    + EntityManagerImpl.class.getPackage()
                    .getImplementationVersion());
        }
        try {
            Constructor<EntityManagerImpl> ct = null;
            Object[] args = null;
            try {
                final Class[] partypes1 = new Class[]{SessionFactory.class, PersistenceContextType.class, PersistenceUnitTransactionType.class, Boolean.TYPE, Map.class};
                ct = EntityManagerImpl.class.getConstructor(partypes1);
                args = new Object[]{sf, persistenceContextType, persistenceUnitTransactionType, TRANSACTION, RESOURCE_LOCAL};
            } catch (Throwable ignored) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Old EntityManagerImpl not detected.");
                }
            }
            if (ct == null) {
                try {
                    final Class[] partypes2 = new Class[]{SessionFactory.class, PersistenceContextType.class, PersistenceUnitTransactionType.class, Boolean.TYPE, Class.class, Map.class};
                    ct = EntityManagerImpl.class.getConstructor(partypes2);
                    args = new Object[]{sf, persistenceContextType, persistenceUnitTransactionType, TRANSACTION, null, RESOURCE_LOCAL};
                } catch (Throwable ex) {
                    throw new RuntimeException("Could not construct new EntityManagerImpl", ex);
                }
            }
            return ct.newInstance(args);
        } catch (Throwable ex) {
            throw new RuntimeException(ex);
        }
    }
}
