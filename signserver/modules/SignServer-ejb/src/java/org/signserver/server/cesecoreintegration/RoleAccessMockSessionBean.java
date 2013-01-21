/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.cesecoreintegration;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;

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
    
    public static final String SUPERADMIN_ROLE = "Super Administrator Role";
    
    private ArrayList<RoleData> allRoles = new ArrayList<RoleData>();

    public RoleAccessMockSessionBean() {
        RoleData role = new RoleData(1, SUPERADMIN_ROLE);
        allRoles.add(role);
        
        Map<Integer, AccessRuleData> rules = role.getAccessRules();
        AccessRuleData rule = new AccessRuleData(SUPERADMIN_ROLE, "/", AccessRuleState.RULE_ACCEPT, true);
        rules.put(1, rule);
        role.setAccessRules(rules);
        
        Map<Integer, AccessUserAspectData> users = role.getAccessUsers();
        
        users.put(0, new AccessUserAspectData(SUPERADMIN_ROLE, 0, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_NOT_EQUALCASE, "NoAccess"));
        
        
//        AccessUserAspectData defaultCliUserAspect = new AccessUserAspectData(SUPERADMIN_ROLE, 0, AccessMatchValue.,
//                AccessMatchType.TYPE_EQUALCASE, "CLI User");
//        if (!users.containsKey(defaultCliUserAspect.getPrimaryKey())) {
//            log.debug("Adding new AccessUserAspect '"+EjbcaConfiguration.getCliDefaultUser()+"' to " + SUPERADMIN_ROLE + ".");
//            Map<Integer, AccessUserAspectData> newUsers = new HashMap<Integer, AccessUserAspectData>();      
//            newUsers.put(defaultCliUserAspect.getPrimaryKey(), defaultCliUserAspect);
            role.setAccessUsers(users);
//            UserData defaultCliUserData = new UserData(EjbcaConfiguration.getCliDefaultUser(), EjbcaConfiguration.getCliDefaultPassword(), false, "UID="
//                    + EjbcaConfiguration.getCliDefaultUser(), 0, null, null, null, 0, SecConst.EMPTY_ENDENTITYPROFILE, 0, 0, 0, null);
//            entityManager.persist(defaultCliUserData);
//        } else {
//            log.debug("AccessUserAspect '"+EjbcaConfiguration.getCliDefaultUser()+"' already exists in " + SUPERADMIN_ROLE + ".");            
//        }
    }
    
    
    
    /**
     * Returns all roles.
     * 
     * @see org.cesecore.roles.management.RoleManagementSession#getAllRoles()
     */
    @SuppressWarnings("unchecked")
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Collection<RoleData> getAllRoles() {
        return allRoles;
    }
    
//    public void createSuperAdministrator() {
//        RoleData role = roleAccessSession.findRole(SUPERADMIN_ROLE);
//        if (role == null) {
//            log.debug("Creating new role '" + SUPERADMIN_ROLE + "'.");
//            role = new RoleData(1, SUPERADMIN_ROLE);
//            entityManager.persist(role);
//        } else {
//            log.debug("'" + SUPERADMIN_ROLE + "' already exists, not creating new.");            
//        }
//
//        Map<Integer, AccessRuleData> rules = role.getAccessRules();
//        AccessRuleData rule = new AccessRuleData(SUPERADMIN_ROLE, AccessRulesConstants.ROLE_ROOT, AccessRuleState.RULE_ACCEPT, true);
//        if (!rules.containsKey(rule.getPrimaryKey())) {
//            log.debug("Adding new rule '/' to " + SUPERADMIN_ROLE + ".");
//            Map<Integer, AccessRuleData> newrules = new HashMap<Integer, AccessRuleData>();
//            newrules.put(rule.getPrimaryKey(), rule);
//            role.setAccessRules(newrules);
//        } else {
//            log.debug("rule '/' already exists in " + SUPERADMIN_ROLE + ".");
//        }
//        Map<Integer, AccessUserAspectData> users = role.getAccessUsers();
//        AccessUserAspectData defaultCliUserAspect = new AccessUserAspectData(SUPERADMIN_ROLE, 0, CliUserAccessMatchValue.USERNAME,
//                AccessMatchType.TYPE_EQUALCASE, EjbcaConfiguration.getCliDefaultUser());
//        if (!users.containsKey(defaultCliUserAspect.getPrimaryKey())) {
//            log.debug("Adding new AccessUserAspect '"+EjbcaConfiguration.getCliDefaultUser()+"' to " + SUPERADMIN_ROLE + ".");
//            Map<Integer, AccessUserAspectData> newUsers = new HashMap<Integer, AccessUserAspectData>();      
//            newUsers.put(defaultCliUserAspect.getPrimaryKey(), defaultCliUserAspect);
//            role.setAccessUsers(newUsers);
//            UserData defaultCliUserData = new UserData(EjbcaConfiguration.getCliDefaultUser(), EjbcaConfiguration.getCliDefaultPassword(), false, "UID="
//                    + EjbcaConfiguration.getCliDefaultUser(), 0, null, null, null, 0, SecConst.EMPTY_ENDENTITYPROFILE, 0, 0, 0, null);
//            entityManager.persist(defaultCliUserData);
//        } else {
//            log.debug("AccessUserAspect '"+EjbcaConfiguration.getCliDefaultUser()+"' already exists in " + SUPERADMIN_ROLE + ".");            
//        }
//    }

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
        return SUPERADMIN_ROLE.equals(roleName) ? allRoles.get(0) : null;
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
        return primaryKey == 1 ? allRoles.get(0) : null;
    }
}
