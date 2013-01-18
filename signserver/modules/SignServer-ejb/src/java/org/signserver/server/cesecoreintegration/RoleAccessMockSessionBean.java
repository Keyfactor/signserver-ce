/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.cesecoreintegration;

import java.util.ArrayList;
import java.util.Collection;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.util.QueryResultWrapper;

/**
 * @version $Id: RoleAccessSessionBean.java 854 2011-05-24 12:57:17Z johane $
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleAccessSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class RoleAccessMockSessionBean implements RoleAccessSessionLocal, RoleAccessSessionRemote {

    // No persistence: @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    // No persistence: private EntityManager entityManager;
    
    /**
     * Returns all roles.
     * 
     * @see org.cesecore.roles.management.RoleManagementSession#getAllRoles()
     */
    @SuppressWarnings("unchecked")
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Collection<RoleData> getAllRoles() {
        return new ArrayList<RoleData>();
    }

    /**
     * Finds a specific role by name.
     * 
     * @see org.cesecore.roles.management.RoleManagementSession#getRole(java.lang.String)
     * 
     * @param token
     *            An authentication token.
     * @param roleName
     *            Name of the sought role.
     * @return The sought roll, null otherwise.
     */
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public RoleData findRole(final String roleName) {
        return null;
    }

    /**
     * Finds a RoleData object by its primary key.
     * 
     * @param primaryKey
     *            The primary key.
     * @return the found entity instance or null if the entity does not exist.
     */
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public RoleData findRole(final Integer primaryKey) {
        return null;
    }
}
