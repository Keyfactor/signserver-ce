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
package se.primekey.sampleapp1.core.ejb.cesecoreintegration;

// No persistence: import javax.ejb.EJBException;
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
            } catch (Exception e) {
                LOG.error(InternalResources.getInstance().getLocalizedMessage("authorization.errorcreateauthtree"), e);
                throw new EJBException(e);
            }
        } else {
            accessTreeUpdateData.setAccessTreeUpdateNumber(accessTreeUpdateData.getAccessTreeUpdateNumber() + 1);
        }*/
    }

}
