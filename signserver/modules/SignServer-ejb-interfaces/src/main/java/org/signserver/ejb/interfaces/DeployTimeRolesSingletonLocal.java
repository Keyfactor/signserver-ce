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
package org.signserver.ejb.interfaces;

import jakarta.ejb.Local;
import org.signserver.common.WorkerConfig;

/**
 * Singleton for loading and providing parsed deploy-time configuration role rules, like
 * for the managed admins.
 */
@Local
public interface DeployTimeRolesSingletonLocal {

    /**
     * @return Parsed deploy-time configuration properties for managed role rules
     */
    WorkerConfig getManagedRulesAsWorkerConfig();

    /**
     * @return if there is any managed rule configured
     */
    boolean isManagedRulesConfigured();
    
}
