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

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.ejb.EJBException;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceException;

import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ResyncException;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.server.GlobalConfigurationCache;
import org.signserver.server.GlobalConfigurationFileParser;
import org.signserver.server.IProcessable;
import org.signserver.server.log.ISystemLogger;
import org.signserver.server.IWorker;
import org.signserver.server.SignServerContext;
import org.signserver.server.log.SystemLoggerException;
import org.signserver.server.log.SystemLoggerFactory;
import org.signserver.server.WorkerFactory;
import org.signserver.server.timedservices.ITimedService;

/**
 * The implementation of the GlobalConfiguration Session Bean.
 * 
 * @see org.signserver.ejb.interfaces.IGlobalConfigurationSession           
 * @version $Id$
 */
@Stateless
public class GlobalConfigurationSessionBean implements IGlobalConfigurationSession.ILocal, IGlobalConfigurationSession.IRemote {

    /** Logger for this class. */
    private static final Logger log = Logger.getLogger(GlobalConfigurationSessionBean.class);
    
    /** Audit logger. */
    private static final ISystemLogger AUDITLOG = SystemLoggerFactory
            .getInstance().getLogger(GlobalConfigurationSessionBean.class);
    
    @PersistenceContext(unitName = "SignServerJPA")
    EntityManager em;
    private static final long serialVersionUID = 1L;

    static {
        SignServerUtil.installBCProvider();
    }

    /**
     * @see org.signserver.ejb.interfaces.IGlobalConfigurationSession#setProperty(String, String, String)
     */
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
                log.error("Error : Invalid scope " + scope);
            }
        }

        return retval;
    }

    /**
     * @see org.signserver.ejb.interfaces.IGlobalConfigurationSession#removeProperty(String, String)
     */
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
                log.error("Error connecting to database, configuration is un-syncronized", e);
                GlobalConfigurationCache.setCurrentState(GlobalConfiguration.STATE_OUTOFSYNC);
                GlobalConfigurationCache.getCachedGlobalConfig().remove(propertyKeyHelper(scope, key));
            }
        }
        return retval;
    }

    /**
     * @see org.signserver.ejb.interfaces.IGlobalConfigurationSession#getGlobalConfiguration()
     */
    public GlobalConfiguration getGlobalConfiguration() {
        GlobalConfiguration retval = null;

        if (GlobalConfigurationCache.getCachedGlobalConfig() == null) {
            GlobalConfigurationFileParser staticConfig = GlobalConfigurationFileParser.getInstance();
            Properties properties = staticConfig.getStaticGlobalConfiguration();

            Iterator<GlobalConfigurationDataBean> iter = getGlobalConfigurationDataService().findAll().iterator();
            while (iter.hasNext()) {
                GlobalConfigurationDataBean data = iter.next();
                String rawkey = data.getPropertyKey();
                if (rawkey.startsWith(GlobalConfiguration.SCOPE_NODE)) {
                    String key = rawkey.replaceFirst(WorkerConfig.getNodeId() + ".", "");
                    properties.setProperty(key, data.getPropertyValue());
                } else {
                    if (rawkey.startsWith(GlobalConfiguration.SCOPE_GLOBAL)) {
                        properties.setProperty(rawkey, data.getPropertyValue());
                    } else {
                        log.error("Illegal property in Global Configuration " + rawkey);
                    }
                }
            }

            GlobalConfigurationCache.setCachedGlobalConfig(properties);
        }
        retval = new GlobalConfiguration(GlobalConfigurationCache.getCachedGlobalConfig(), GlobalConfigurationCache.getCurrentState());

        return retval;
    }

    /**
     * @see org.signserver.ejb.interfaces.IGlobalConfigurationSession#getWorkers(int)
     */
    public List<Integer> getWorkers(int workerType) {
        ArrayList<Integer> retval = new ArrayList<Integer>();
        GlobalConfiguration gc = getGlobalConfiguration();

        Enumeration<String> en = gc.getKeyEnumeration();
        while (en.hasMoreElements()) {
            String key = en.nextElement();
            if (log.isTraceEnabled()) {
                log.trace("getWorkers, processing key : " + key);
            }
            if (key.startsWith("GLOB.WORKER")) {
                retval = (ArrayList<Integer>) getWorkerHelper(retval, gc, key, workerType, false);
            }
            if (key.startsWith("GLOB.SIGNER")) {
                retval = (ArrayList<Integer>) getWorkerHelper(retval, gc, key, workerType, true);
            }
        }
        return retval;
    }

    private List<Integer> getWorkerHelper(List<Integer> retval, GlobalConfiguration gc, String key, int workerType, boolean signersOnly) {

        String unScopedKey = key.substring("GLOB.".length());
        if (log.isTraceEnabled()) {
            log.trace("unScopedKey : " + unScopedKey);
        }
        String strippedKey = key.substring("GLOB.WORKER".length());
        if (log.isTraceEnabled()) {
            log.trace("strippedKey : " + strippedKey);
        }
        String[] splittedKey = strippedKey.split("\\.");
        if (log.isTraceEnabled()) {
            log.trace("splittedKey : " + splittedKey.length + ", " + splittedKey[0]);
        }
        if (splittedKey.length > 1) {
            if (splittedKey[1].equals("CLASSPATH")) {
                int id = Integer.parseInt(splittedKey[0]);
                if (workerType == GlobalConfiguration.WORKERTYPE_ALL) {
                    retval.add(new Integer(id));
                } else {
                    IWorker obj = WorkerFactory.getInstance().getWorker(id, new WorkerConfigDataService(em), this, new SignServerContext(em));
                    if (workerType == GlobalConfiguration.WORKERTYPE_PROCESSABLE) {
                        if (obj instanceof IProcessable) {
                            if (log.isDebugEnabled()) {
                                log.debug("Adding Signer " + id);
                            }
                            retval.add(new Integer(id));
                        }
                    } else {
                        if (workerType == GlobalConfiguration.WORKERTYPE_SERVICES && !signersOnly) {
                            if (obj instanceof ITimedService) {
                                if (log.isDebugEnabled()) {
                                    log.debug("Adding Service " + id);
                                }
                                retval.add(new Integer(id));
                            }
                        }
                    }
                }
            }
        }
        return retval;
    }

    /**
     * @see org.signserver.ejb.interfaces.IGlobalConfigurationSession#resync()
     */
    public void resync() throws ResyncException {

        auditLog("resync", null, null); // TODO Should handle errors

        if (!GlobalConfigurationCache.getCurrentState().equals(GlobalConfiguration.STATE_OUTOFSYNC)) {
            String message = "Error it is only possible to resync a database that have the state " + GlobalConfiguration.STATE_OUTOFSYNC;
            log.error(message);
            throw new ResyncException(message);
        }
        if (GlobalConfigurationCache.getCachedGlobalConfig() == null) {
            String message = "Error resyncing database, cached global configuration doesn't exist.";
            log.error(message);
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
            log.error(message);
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
    public void reload() {
        auditLog("reload", null, null);

        GlobalConfigurationFileParser.getInstance().reloadConfiguration();
        GlobalConfigurationCache.setCachedGlobalConfig(null);
        getGlobalConfiguration();

        // Set the state to insync.
        GlobalConfigurationCache.setCurrentState(GlobalConfiguration.STATE_INSYNC);
    }

    /**
     * Helper method used to set properties in a table.
     * @param tempKey
     * @param value
     * @throws SQLException 
     */
    private void setPropertyHelper(String key, String value) {
        try {
            getGlobalConfigurationDataService().setGlobalProperty(key, value);
            GlobalConfigurationCache.setCachedGlobalConfig(null);
        } catch (Throwable e) {
            String message = "Error connecting to database, configuration is un-syncronized :";
            log.error(message, e);
            GlobalConfigurationCache.setCurrentState(GlobalConfiguration.STATE_OUTOFSYNC);
            GlobalConfigurationCache.getCachedGlobalConfig().setProperty(key, value);
        }

    }
    private GlobalConfigurationDataService globalConfigurationDataService = null;

    private GlobalConfigurationDataService getGlobalConfigurationDataService() {
        if (globalConfigurationDataService == null) {
            globalConfigurationDataService = new GlobalConfigurationDataService(em);
        }
        return globalConfigurationDataService;
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
            log.error("Audit log failure", ex);
            throw new EJBException("Audit log failure", ex);
        }
    }
}
