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
package org.signserver.admin.common.auth;

import java.security.Principal;
import java.util.List;
import org.signserver.server.log.AdminInfo;

/**
 * Administrator info and roles.
 */
public interface AdminPrincipal extends Principal {

    /**
     * @return Authenticated admin information.
     */
    AdminInfo getAdminInfo();

    /**
     * @return Authorized roles this admin belongs to.
     */
    List<String> getRoles();

}
