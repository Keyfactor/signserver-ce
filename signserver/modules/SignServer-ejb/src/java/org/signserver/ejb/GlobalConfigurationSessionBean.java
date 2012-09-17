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
package org.signserver.ejb;

import java.util.*;
import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceException;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.worker.impl.IWorkerManagerSessionLocal;
import org.signserver.server.GlobalConfigurationCache;
import org.signserver.server.config.entities.FileBasedGlobalConfigurationDataService;
import org.signserver.server.config.entities.GlobalConfigurationDataBean;
import org.signserver.server.config.entities.GlobalConfigurationDataService;
import org.signserver.server.config.entities.IGlobalConfigurationDataService;
import org.signserver.server.log.ISystemLogger;
import org.signserver.server.log.SystemLoggerException;
import org.signserver.server.log.SystemLoggerFactory;
import org.signserver.server.nodb.FileBasedDatabaseManager;

/**
 * The implementation of the GlobalConfiguration Session Bean.
 * 
 * @see org.signserver.ejb.interfaces.IGlobalConfigurationSession           
 * @version $Id$
 */
@Stateless
public class GlobalConfigurationSessionBean implements IGlobalConfigurationSession.ILocal, IGlobalConfigurationSession.IRemote {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(GlobalConfigurationSessionBean.class);
    
    /** Audit logger. */
    private static final ISystemLogger AUDITLOG = SystemLoggerFactory
            .getInstance().getLogger(GlobalConfigurationSessionBean.class);

    @EJB
    private IWorkerManagerSessionLocal workerManagerSession;
    

    EntityManager em;

    private static final long serialVersionUID = 1L;

    static {
        SignServerUtil.installBCProvider();
    }

    private IGlobalConfigurationDataService globalConfigurationDataService;
    
    @PostConstruct
    public void create() {
        if (em == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No EntityManager injected. Running without database.");
            }
            globalConfigurationDataService = new FileBasedGlobalConfigurationDataService(FileBasedDatabaseManager.getInstance());
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("EntityManager injected. Running with database.");
            }
            globalConfigurationDataService = new GlobalConfigurationDataService(em);
        }
    }
    
    private IGlobalConfigurationDataService getGlobalConfigurationDataService() {
        return globalConfigurationDataService;
    }
    
    /**
     * @see org.signserver.ejb.interfaces.IGlobalConfigurationSession#setProperty(String, String, String)
     */
    @Override
    public void setProperty(String scope, String key, String value) {

        auditLog("setProperty", scope + key, value);

        if (GlobalConfigurationCache.getCurrentState().equals(GlobalConfiguration.STATE_OUTOFSYNC)) {
            GlobalConfigurationCache.getCachedGlobalConfig().setProperty(propertyKeyHelper(scope, key), value);
        } else {
            setPropertyHelper(propertyKeyHelper(scope, key), value);
        }
    }

    private String propertyKeyHelper(String scope, String key) {
        String retval = null;
        String tempKey = key.toUpperCase();

        if (scope.equals(GlobalConfiguration.SCOPE_NODE)) {
            retval = GlobalConfiguration.SCOPE_NODE + WorkerConfig.getNodeId() + "." + tempKey;
        } else {
            if (scope.equals(GlobalConfiguration.SCOPE_GLOBAL)) {
                retval = GlobalConfiguration.SCOPE_GLOBAL + tempKey;
            } else {
                LOG.error("Error : Invalid scope " + scope);
            }
        }

        return retval;
    }

    /**
     * @see org.signserver.ejb.interfaces.IGlobalConfigurationSession#removeProperty(String, String)
     */
    @Override
    public boolean removeProperty(String scope, String key) {
        boolean retval = false;

        auditLog("removeProperty", scope + key, null);

        if (GlobalConfigurationCache.getCurrentState().equals(GlobalConfiguration.STATE_OUTOFSYNC)) {
            GlobalConfigurationCache.getCachedGlobalConfig().remove(propertyKeyHelper(scope, key));
        } else {
            try {
                retval = getGlobalConfigurationDataService().removeGlobalProperty(propertyKeyHelper(scope, key));
                GlobalConfigurationCache.setCachedGlobalConfig(null);
            } catch (Throwable e) {
                LOG.error("Error connecting to database, configuration is un-syncronized", e);
                GlobalConfigurationCache.setCurrentState(GlobalConfiguration.STATE_OUTOFSYNC);
                GlobalConfigurationCache.getCachedGlobalConfig().remove(propertyKeyHelper(scope, key));
            }
        }
        return retval;
    }

    /**
     * @see org.signserver.ejb.interfaces.IGlobalConfigurationSession#getGlobalConfiguration()
     */
    @Override
    public GlobalConfiguration getGlobalConfiguration() {
        GlobalConfiguration retval = null;

        if (GlobalConfigurationCache.getCachedGlobalConfig() == null) {
            Properties properties = new Properties();

            Iterator<GlobalConfigurationDataBean> iter = getGlobalConfigurationDataService().findAll().iterator();
            while (iter.hasNext()) {
                GlobalConfigurationDataBean data = iter.next();
                String rawkey = data.getPropertyKey();
                String propertyValue = data.getPropertyValue();
                
                if (rawkey.startsWith(GlobalConfiguration.SCOPE_NODE)) {
                    String key = rawkey.replaceFirst(WorkerConfig.getNodeId() + ".", "");
                    properties.setProperty(key, propertyValue == null ? "" : propertyValue);
                } else {
                    if (rawkey.startsWith(GlobalConfiguration.SCOPE_GLOBAL)) {
                    	properties.setProperty(rawkey,
                    			propertyValue == null ? "" : propertyValue);
                    } else {
                        LOG.error("Illegal property in Global Configuration " + rawkey);
                    }
                }
            }

            GlobalConfigurationCache.setCachedGlobalConfig(properties);
        }
        retval = new GlobalConfiguration(GlobalConfigurationCache.getCachedGlobalConfig(), 
                GlobalConfigurationCache.getCurrentState(), 
                CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_VERSION));

        return retval;
    }

    /**
     * @see org.signserver.ejb.interfaces.IGlobalConfigurationSession#resync()
     */
    @Override
    public void resync() throws ResyncException {

        auditLog("resync", null, null); // TODO Should handle errors

        if (!GlobalConfigurationCache.getCurrentState().equals(GlobalConfiguration.STATE_OUTOFSYNC)) {
            String message = "Error it is only possible to resync a database that have the state " + GlobalConfiguration.STATE_OUTOFSYNC;
            LOG.error(message);
            throw new ResyncException(message);
        }
        if (GlobalConfigurationCache.getCachedGlobalConfig() == null) {
            String message = "Error resyncing database, cached global configuration doesn't exist.";
            LOG.error(message);
            throw new ResyncException(message);
        }

        String thisNodeConfig = GlobalConfiguration.SCOPE_NODE + WorkerConfig.getNodeId() + ".";
        // remove all global and node specific properties
        try {
            Collection<GlobalConfigurationDataBean> allProperties = getGlobalConfigurationDataService().findAll();
            Iterator<GlobalConfigurationDataBean> iter = allProperties.iterator();
            while (iter.hasNext()) {
                GlobalConfigurationDataBean data = iter.next();
                if (data.getPropertyKey().startsWith(GlobalConfiguration.SCOPE_GLOBAL)) {
                    getGlobalConfigurationDataService().removeGlobalProperty(data.getPropertyKey());
                } else {
                    if (data.getPropertyKey().startsWith(thisNodeConfig)) {
                        getGlobalConfigurationDataService().removeGlobalProperty(data.getPropertyKey());
                    }
                }
            }

        } catch (PersistenceException e) {
            String message = e.getMessage();
            LOG.error(message);
            throw new ResyncException(message);
        }

        // add all properties
        Iterator<?> keySet = GlobalConfigurationCache.getCachedGlobalConfig().keySet().iterator();
        while (keySet.hasNext()) {
            String fullKey = (String) keySet.next();

            if (fullKey.startsWith(GlobalConfiguration.SCOPE_GLOBAL)) {
                String scope = GlobalConfiguration.SCOPE_GLOBAL;
                String key = fullKey.substring(GlobalConfiguration.SCOPE_GLOBAL.length());

                setProperty(scope, key, GlobalConfigurationCache.getCachedGlobalConfig().getProperty(fullKey));
            } else {
                if (fullKey.startsWith(GlobalConfiguration.SCOPE_NODE)) {
                    String scope = GlobalConfiguration.SCOPE_NODE;
                    String key = fullKey.substring(thisNodeConfig.length());
                    setProperty(scope, key, GlobalConfigurationCache.getCachedGlobalConfig().getProperty(fullKey));
                }
            }
        }

        // Set the state to insync.
        GlobalConfigurationCache.setCurrentState(GlobalConfiguration.STATE_INSYNC);
    }

    /**
     * @see org.signserver.ejb.interfaces.IGlobalConfigurationSession#reload()
     */
    @Override
    public void reload() {
        auditLog("reload", null, null);

        workerManagerSession.flush();
        GlobalConfigurationCache.setCachedGlobalConfig(null);
        getGlobalConfiguration();

        // Set the state to insync.
        GlobalConfigurationCache.setCurrentState(GlobalConfiguration.STATE_INSYNC);
    }
    
    /**
     * Helper method used to set properties in a table.
     * @param tempKey
     * @param value
     */
    private void setPropertyHelper(String key, String value) {
        try {
            getGlobalConfigurationDataService().setGlobalProperty(key, value);
            GlobalConfigurationCache.setCachedGlobalConfig(null);
        } catch (Throwable e) {
            String message = "Error connecting to database, configuration is un-syncronized :";
            LOG.error(message, e);
            GlobalConfigurationCache.setCurrentState(GlobalConfiguration.STATE_OUTOFSYNC);
            GlobalConfigurationCache.getCachedGlobalConfig().setProperty(key, value);
        }

    }

    private static void auditLog(final String operation, final String property,
            final String value) {
        try {
            final Map<String, String> logMap = new HashMap<String, String>();

            logMap.put(ISystemLogger.LOG_CLASS_NAME,
                    GlobalConfigurationSessionBean.class.getSimpleName());
            logMap.put(IGlobalConfigurationSession.LOG_OPERATION,
                    operation);
            logMap.put(IGlobalConfigurationSession.LOG_PROPERTY,
                    property);
            if (value != null) {
                logMap.put(IGlobalConfigurationSession.LOG_VALUE,
                        value);
            }
            AUDITLOG.log(logMap);
        } catch (SystemLoggerException ex) {
            LOG.error("Audit log failure", ex);
            throw new EJBException("Audit log failure", ex);
        }
    }
}
