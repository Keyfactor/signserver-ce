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

// No persistence: import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import org.cesecore.authorization.access.AuthorizationCacheReloadListener;
import org.cesecore.authorization.cache.AccessTreeUpdateData;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.jndi.JndiConstants;

/**
 * Mocked version as we don't handle access tree updates.
 * 
 * Based on AccessTreeUpdateSessionBean.java 25573 2017-03-22 00:42:52Z jeklund from CESeCore
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

    // No persistence: private static final Logger LOG = Logger.getLogger(AccessTreeUpdateMockSessionBean.class);

    // No persistence: @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    // No persistence: private EntityManager entityManager;

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)    // We don't modify the database in this call
    public int getAccessTreeUpdateNumber() {
        // No persistence: final AccessTreeUpdateData accessTreeUpdateData = entityManager.find(AccessTreeUpdateData.class, AccessTreeUpdateData.AUTHORIZATIONTREEUPDATEDATA);
        // No persistence: if (accessTreeUpdateData==null) {
        // No persistence:     // No update has yet been persisted, so we return the default value
            return AccessTreeUpdateData.DEFAULTACCESSTREEUPDATENUMBER;
        // No persistence: }
        // No persistence: return accessTreeUpdateData.getAccessTreeUpdateNumber();
    }

    @Override
    public void signalForAccessTreeUpdate() {
        /* No persistence: AccessTreeUpdateData accessTreeUpdateData = entityManager.find(AccessTreeUpdateData.class, AccessTreeUpdateData.AUTHORIZATIONTREEUPDATEDATA);
        if (accessTreeUpdateData==null) {
            // We need to create the database row and incremented the value directly since this is an call to update it
            try {
                accessTreeUpdateData = new AccessTreeUpdateData();
                accessTreeUpdateData.setAccessTreeUpdateNumber(AccessTreeUpdateData.DEFAULTACCESSTREEUPDATENUMBER+1);
                entityManager.persist(accessTreeUpdateData);
                // Additionally we set the marker that this (new) installation should use the new union access rule pattern
                setNewAuthorizationPatternMarker();
            } catch (Exception e) {
                LOG.error(InternalResources.getInstance().getLocalizedMessage("authorization.errorcreateauthtree"), e);
                throw new EJBException(e);
            }
        } else {
            accessTreeUpdateData.setAccessTreeUpdateNumber(accessTreeUpdateData.getAccessTreeUpdateNumber() + 1);
        }
        LOG.debug("Invoking event");
        final AuthorizationCacheReload event = new AuthorizationCacheReload(accessTreeUpdateData.getAccessTreeUpdateNumber());
        AuthorizationCacheReloadListeners.INSTANCE.onReload(event);
        LOG.debug("Done invoking event");
        */
    }

    @Override
    public void addReloadEvent(final AuthorizationCacheReloadListener observer) {
        // No persistence: AuthorizationCacheReloadListeners.INSTANCE.addListener(observer);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean isNewAuthorizationPatternMarkerPresent() {
        // No persistence: return entityManager.find(AccessTreeUpdateData.class, AccessTreeUpdateData.NEW_AUTHORIZATION_PATTERN_MARKER)!=null;
        return false;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void setNewAuthorizationPatternMarker() {
        /* No persistence
         * Use a row in this table as a marker, since it is already a dependency from AuthorizationSessionBean.
         * (Otherwise we would have to depend on reading configuration which in turn depends back on authorization.)
         *
        if (!isNewAuthorizationPatternMarkerPresent()) {
            final AccessTreeUpdateData marker = new AccessTreeUpdateData();
            marker.setPrimaryKey(AccessTreeUpdateData.NEW_AUTHORIZATION_PATTERN_MARKER);
            entityManager.persist(marker);
        }*/
    }
}
