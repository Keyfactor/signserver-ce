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

import java.util.List;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import org.apache.log4j.Logger;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleDataSessionLocal;

/**
 * Mocked implementation of the RoleDataSession local interface.
 * 
 * @version $Id$
 */
@Stateless//(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleDataSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RoleDataMockSessionBean implements RoleDataSessionLocal {

    private static final Logger log = Logger.getLogger(RoleDataMockSessionBean.class);

    @Override
    public List<Role> getAllRoles() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Role getRole(int id) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Role getRole(String roleName, String nameSpace) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean deleteRoleNoAuthorizationCheck(int roleId) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Role persistRole(Role role) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void forceCacheExpire() {
        throw new UnsupportedOperationException();
    }

}
