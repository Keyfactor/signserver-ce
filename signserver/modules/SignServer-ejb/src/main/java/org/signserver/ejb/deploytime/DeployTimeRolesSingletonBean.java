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
package org.signserver.ejb.deploytime;

import jakarta.annotation.PostConstruct;
import jakarta.ejb.ConcurrencyManagement;
import jakarta.ejb.ConcurrencyManagementType;
import jakarta.ejb.Lock;
import jakarta.ejb.LockType;
import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;
import org.apache.log4j.Logger;
import org.signserver.common.CompileTimeSettings;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.DeployTimeRolesSingletonLocal;

/**
 * Singleton for loading and providing parsed deploy-time configuration role rules, like
 * for the managed admins.
 */
@Startup
@Singleton
@ConcurrencyManagement(ConcurrencyManagementType.CONTAINER)
@Lock(LockType.READ)
public class DeployTimeRolesSingletonBean implements DeployTimeRolesSingletonLocal {
    private static final Logger LOG = Logger.getLogger(DeployTimeRolesSingletonBean.class);

    private WorkerConfig managedRulesAsWorkerConfig;
    private boolean managedRulesConfigured;

    @PostConstruct
    protected void startup() {
        LOG.trace(">Initializes deploy-time roles");

        // Init Managed role rules
        try {
            managedRulesAsWorkerConfig = ManagedAuthorizerUtil.parse(CompileTimeSettings.getInstance().getManagedAuthProperties());
            if (LOG.isInfoEnabled()) {
                LOG.info("Loaded " + managedRulesAsWorkerConfig.getProperties().size() + " managed admin properties");
            }
            managedRulesConfigured = !managedRulesAsWorkerConfig.getProperties().isEmpty();
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Failed to parse managed admin rules. Please check your managed.admincert.* deploy-time properties.", ex);
        }
    }

    @Override
    public WorkerConfig getManagedRulesAsWorkerConfig() {
        return managedRulesAsWorkerConfig;
    }

    @Override
    public boolean isManagedRulesConfigured() {
        return managedRulesConfigured;
    }

}
