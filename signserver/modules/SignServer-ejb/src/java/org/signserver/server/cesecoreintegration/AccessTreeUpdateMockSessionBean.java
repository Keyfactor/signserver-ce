/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.server.cesecoreintegration;

import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import org.apache.log4j.Logger;
import org.cesecore.authorization.cache.AccessTreeUpdateData;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;

/**
 * Mocked version as we don't handle access tree updates.
 * 
 * Based on AccessTreeUpdateSessionBean.java 461 2011-03-08 09:40:15Z tomas from CESeCore
 * 
 * Bean to handle the AuthorizationTreeUpdateData entity.
 * 
 * Based on AuthorizationTreeUpdateDataSessionBean.java 10845 2010-12-14 10:37:21Z anatom from EJBCA
 * 
 * 
 * @version $Id: AccessTreeUpdateSessionBean.java 461 2011-03-08 09:40:15Z tomas $
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AccessTreeUpdateSessionLocal")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AccessTreeUpdateMockSessionBean implements AccessTreeUpdateSessionLocal {

    private static final Logger LOG = Logger.getLogger(AccessTreeUpdateMockSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources INTERNAL_RESOURCES = InternalResources.getInstance();

    // No persistence: @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    // No persistence: private EntityManager entityManager;

    /**
     * Cache this local bean, because it will cause many many database lookups otherwise
     */
    private AccessTreeUpdateData authTreeData = null;

    /**
     * Returns a reference to the AuthorizationTreeUpdateData
     */
    @Override
    public AccessTreeUpdateData getAccessTreeUpdateData() {
        if (authTreeData == null) {
            authTreeData = findByPrimaryKey(AccessTreeUpdateData.AUTHORIZATIONTREEUPDATEDATA);
            if (authTreeData == null) {
                try {
                    final AccessTreeUpdateData temp = new AccessTreeUpdateData();
                    // No persistence: entityManager.persist(temp);
                    authTreeData = temp;
                } catch (Exception e) {
                    final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorcreateauthtree");
                    LOG.error(msg, e);
                    throw new EJBException(e);
                }
            }
        }
        return authTreeData;
    }

    /**
     * Method incrementing the authorization tree update number and thereby signaling to other beans that they should reconstruct their access trees.
     */
    @Override
    public void signalForAccessTreeUpdate() {
        getAccessTreeUpdateData().incrementAccessTreeUpdateNumber();
    }

    /**
     * Finds a AccessTreeUpdateData object by its primary key. Note that this object will not be in context.
     * 
     * @return the found entity instance or null if the entity does not exist.
     */
    private AccessTreeUpdateData findByPrimaryKey(final Integer primaryKey) {
        // No persistence: return entityManager.find(AccessTreeUpdateData.class, primaryKey);
        return null;
    }

}
