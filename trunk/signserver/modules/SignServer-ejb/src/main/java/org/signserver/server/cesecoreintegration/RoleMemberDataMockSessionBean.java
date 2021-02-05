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


import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberData;
import org.cesecore.roles.member.RoleMemberDataSessionLocal;
import org.cesecore.roles.member.RoleMemberDataSessionRemote;
import org.cesecore.util.ProfileID;

/**
 * Mocked implementation of RoleMemberDataSessionLocal and RoleMemberDataSessionRemote.
 *
 * @see RoleMemberSessionDataLocal
 * 
 * @version $Id: RoleMemberDataSessionBean.java 25642 2017-04-03 16:27:48Z jeklund $
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleMemberDataSessionRemote")
//@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RoleMemberDataMockSessionBean implements RoleMemberDataSessionLocal, RoleMemberDataSessionRemote {

    private static final Logger log = Logger.getLogger(RoleMemberDataMockSessionBean.class);

    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;

    @Override
    public RoleMember persistRoleMember(final RoleMember roleMember) {
        return null;
    }

    private int findFreePrimaryKey() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                //0 is a protected ID for RoleMemberData. Use only positive values, since negatives are seen as "erronous" by some customers.
                return find(i) == null && i > 0;
            }
        };
        return ProfileID.getNotUsedID(db);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public RoleMemberData find(final int primaryKey) {
        return null;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public RoleMember findRoleMember(int primaryKey) {
        return null;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<RoleMemberData> findByRoleId(int roleId) {
        return Collections.emptyList();
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<RoleMember> findRoleMemberByRoleId(int roleId) {
        return Collections.emptyList();
    }

    @Override
    public boolean remove(final int primaryKey) {
        return false;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Set<Integer> getRoleIdsMatchingAuthenticationToken(final AuthenticationToken authenticationToken) {
        return Collections.emptySet();
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Set<Integer> getRoleIdsMatchingAuthenticationTokenOrFail(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        return Collections.emptySet();
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Set<RoleMember> getRoleMembersMatchingAuthenticationToken(final AuthenticationToken authenticationToken) {
        return Collections.emptySet();
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    @Deprecated
    public Map<Integer,Integer> getRoleIdsAndTokenMatchKeysMatchingAuthenticationToken(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        final Map<Integer,Integer> ret = new HashMap<>();
        return ret;
    }

    @Override
    public void forceCacheExpire() {
        // do nothing here
    }

}
