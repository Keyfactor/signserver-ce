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

import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.signserver.common.CompileTimeSettings;
import org.signserver.common.FileBasedDatabaseException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.PKCS11Settings;
import org.signserver.common.WorkerConfig;
import static org.signserver.common.util.PropertiesConstants.GLOBAL_PREFIX_DOT;
import static org.signserver.common.util.PropertiesConstants.OLDWORKER_PREFIX;
import static org.signserver.common.util.PropertiesConstants.WORKER_PREFIX;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IServiceTimerSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.ejb.worker.impl.WorkerManagerSingletonBean;
import org.signserver.server.cesecore.AlwaysAllowLocalAuthenticationToken;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.log.SignServerEventTypes;
import org.signserver.server.log.SignServerModuleTypes;
import org.signserver.server.log.SignServerServiceTypes;
import org.signserver.server.nodb.FileBasedDatabaseManager;
import org.signserver.statusrepo.IStatusRepositorySession;
import org.signserver.statusrepo.common.NoSuchPropertyException;
import org.signserver.statusrepo.common.StatusEntry;
import org.signserver.statusrepo.common.StatusName;

/**
 * EJB Singleton used to start services and perform upgrades etc.
 * 
 * @version $Id$
 */
@Startup
@Singleton
public class StartupSingletonBean {

    private static final long serialVersionUID = 1L;
    
    private static final String LOG_VERSION = "VERSION";
    
    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(StartupSingletonBean.class);
    
    @EJB
    private IServiceTimerSession.ILocal timedServiceSession;

    @EJB
    private IStatusRepositorySession.ILocal statusRepositorySession;

    @EJB
    private IGlobalConfigurationSession.ILocal globalSession;
    
    @EJB
    private IWorkerSession.ILocal workerSession;

    @EJB
    private SecurityEventsLoggerSessionLocal logSession;

    @EJB
    private WorkerManagerSingletonBean workerManager;

    private IServiceTimerSession.ILocal getTimedServiceSession(){
    	return timedServiceSession;
    }

    private IStatusRepositorySession.ILocal getStatusRepositorySession() {
        return statusRepositorySession;
    }


    @PreDestroy
    private void destroy() {
        final String version = CompileTimeSettings.getInstance().getProperty(
                CompileTimeSettings.SIGNSERVER_VERSION);

        LOG.info("Destroy,  " + version + " shutdown.");
        
        // Try to unload the timers
        LOG.debug(">destroy calling ServiceSession.unload");
        try {
            getTimedServiceSession().unload(0);
        } catch (Exception ex) {
            LOG.info("Exception caught trying to cancel timers. This happens with some application servers: " + ex.getMessage());
        }
    }

    @PostConstruct
    private void startup() {
        final CompileTimeSettings settings = CompileTimeSettings.getInstance();
        final String version = settings.getProperty(
                CompileTimeSettings.SIGNSERVER_VERSION);
        
        LOG.info("Init, " + version + " startup.");
      
        // Make a log row that EJBCA is starting
        AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("StartServicesServlet.init"));
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", "start services startup msg");
        details.put(LOG_VERSION, version);
        try {
            logSession.log(SignServerEventTypes.SIGNSERVER_STARTUP, EventStatus.SUCCESS, SignServerModuleTypes.SERVICE, SignServerServiceTypes.SIGNSERVER, admin.toString(), null, null, null, details);
        } catch (AuditRecordStorageException ex) {
            LOG.error("Logging", ex);
            throw new EJBException("Could not log", ex);
        }
        
        // instanciate the P11 libraries to avoid possible race-conditions
        // later on then init:ing crypto tokens, this will also debug log
        // the available libraries when debug logging is turned on
        final PKCS11Settings p11Settings = PKCS11Settings.getInstance();

        // Cancel old timers as we can not rely on them being cancelled at shutdown
        LOG.debug(">init calling ServiceSession.unload");
        getTimedServiceSession().unload(0);
        
        LOG.debug(">init FileBasedDataseManager");
        final FileBasedDatabaseManager nodb = FileBasedDatabaseManager.getInstance();
        if (nodb.isUsed()) {
            try {
                nodb.initialize();
            } catch (FileBasedDatabaseException ex) {
                throw new EJBException(ex.getMessage());
            }
            
            final List<String> fatalErrors = nodb.getFatalErrors();
            if (!fatalErrors.isEmpty()) {
                final StringBuilder buff = new StringBuilder();
                buff.append("Error initializing file based database manager: ");
                buff.append(fatalErrors);
                LOG.error(buff.toString());
                throw new EJBException(buff.toString());
            }
        }

        // Perform database upgrade if needed
        LOG.debug(">init database upgrade");
        upgradeDatabase(new AdminInfo("CLI user", null, null));
        
        LOG.debug(">init calling ServiceSession.load");
        
        // Start the timed services session
        getTimedServiceSession().load(0);

        // Instantiate the status repository session and list all available status properties
        LOG.debug(">init StatusReposotorySession");
        try {
            getStatusRepositorySession().update(StatusName.SERVER_STARTED.name(), String.valueOf(System.currentTimeMillis()));
            for(Map.Entry<String, StatusEntry> entry : getStatusRepositorySession().getAllEntries().entrySet()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Status property: " + entry.getKey() + " = " + entry.getValue());
                }
            }
        } catch (NoSuchPropertyException ex) {
            throw new EJBException(ex);
        }
        
    }

    private static final String CRYPTOTOKENPROPERTY_BASE = ".CRYPTOTOKEN";
    private static final String OLD_CRYPTOTOKENPROPERTY_BASE = ".SIGNERTOKEN";
    private static final String CRYPTOTOKENPROPERTY_CLASSPATH = ".CLASSPATH";
    
    private void upgradeDatabase(AdminInfo admin) {
        
        // Perform the upgrade from DSS-1055
        final GlobalConfiguration globalConfig = globalSession.getGlobalConfiguration();
        final Enumeration<String> keys = globalConfig.getKeyEnumeration();
        while (keys.hasMoreElements()) {
            final String key = keys.nextElement();
            
            if (key.startsWith(GLOBAL_PREFIX_DOT)) {
                String strippedKey = key.substring(GLOBAL_PREFIX_DOT.length());
                if (strippedKey.startsWith(WORKER_PREFIX) || strippedKey.startsWith(OLDWORKER_PREFIX)) {
                    try {
                        final String strippedKey2;
                        if (strippedKey.startsWith(WORKER_PREFIX)) {
                            strippedKey2 = strippedKey.substring(WORKER_PREFIX.length());
                        } else {
                            strippedKey2 = strippedKey.substring(OLDWORKER_PREFIX.length());
                        }

                        String splittedKey = strippedKey2.substring(0, strippedKey2.indexOf('.'));
                        String propertykey = strippedKey2.substring(strippedKey2.indexOf('.') + 1);
                        final int workerid = Integer.parseInt(splittedKey);

                        if (propertykey.equalsIgnoreCase(GlobalConfiguration.WORKERPROPERTY_CLASSPATH.substring(1))) {
                            if (!workerSession.getCurrentWorkerConfig(workerid).getProperties().containsKey(WorkerConfig.IMPLEMENTATION_CLASS)) {
                                workerSession.setWorkerProperty(admin, workerid, WorkerConfig.IMPLEMENTATION_CLASS, globalConfig.getProperty(key));
                                LOG.info("Upgraded config for worker " + workerid);
                            } else {
                                LOG.debug("Worker " + workerid + " already upgraded");
                            }
                        } else if (propertykey.equalsIgnoreCase("CRYPTOTOKEN.CLASSPATH") 
                                    || propertykey.equalsIgnoreCase("SIGNERTOKEN.CLASSPATH")) {
                            
                            if (!workerSession.getCurrentWorkerConfig(workerid).getProperties().containsKey(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS)) {
                                workerSession.setWorkerProperty(admin, workerid, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, globalConfig.getProperty(key));
                                LOG.info("Upgraded crypto config for worker " + workerid);
                            } else {
                                LOG.debug("Worker " + workerid + " cryptotoken already upgraded");
                            }
                        }
                    } catch (Exception ex) {
                        LOG.error("Upgrade failed for global config property: " + strippedKey, ex);
                    }
                }
            }
        }
        
        // Perform the upgrade from DSS-1058
        workerManager.upgradeWorkerNames();
    }
}
