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
package org.signserver.ejb.worker.impl;

import java.util.*;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.common.util.PropertiesConstants;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.server.*;
import org.signserver.server.archive.Archiver;
import org.signserver.server.archive.ArchiverInitException;
import org.signserver.server.archive.olddbarchiver.OldDatabaseArchiver;
import org.signserver.server.config.entities.IWorkerConfigDataService;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.log.AllFieldsWorkerLogger;
import org.signserver.server.log.IWorkerLogger;

/**
 * Class used to manage different signers used in the system, uses the configuration in
 * GlobalConfigurationFileParser as a backup.
 * 
 * XXX: Large scary singleton. Consider re-design.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class WorkerFactory {

    /** Logger for this class. */
    public static final Logger LOG = Logger.getLogger(WorkerFactory.class);
    
    private static final String WORKERLOGGER = "WORKERLOGGER";
    
    private static final String ACCOUNTER = "ACCOUNTER";
    
    private static final WorkerFactory INSTANCE = new WorkerFactory();
    
    private Map<Integer, IWorker> workerStore;
    
    private Map<Integer, IAuthorizer> authenticatorStore;
    
    private Map<String, Integer> nameToIdMap;
    
    private Map<Integer, IWorkerLogger> workerLoggerStore;
    
    private Map<Integer, IAccounter> accounterStore;
    
    private final Map<Integer, List<Archiver>> archiversStore  = new HashMap<Integer, List<Archiver>>();
    
    private WorkerFactory() {}

    protected synchronized static WorkerFactory getInstance() {
        return INSTANCE;
    }

    /**
     * Method returning a worker given it's id. The signer should be defined in 
     * the global configuration along with it's id.
     * 
     * The worker will only be created upon first call, then it's stored in memory until
     * the flush method is called.
     * 
     * @param signerId the Id that should match the one in the config file.
     * @param workerConfigHome The service interface of the signer config entity bean
     * @param gCSession
     * @param workerContext
     * @return A ISigner as defined in the configuration file, or null if no configuration
     * for the specified signerId could be found.
     */
    public synchronized IWorker getWorker(int workerId, 
            IWorkerConfigDataService workerConfigHome, 
            IGlobalConfigurationSession gCSession, 
            IWorkerManagerSessionLocal workerManagerSession,
            SignServerContext workerContext) {
        Integer id = new Integer(workerId);

        loadWorkers(workerConfigHome, gCSession, workerManagerSession, workerContext);
        IWorker ret = (IWorker) workerStore.get(id);
        if (ret == null) {
            LOG.info("Trying to get worker with Id that does not exist: " + workerId);
        }
        return ret;
    }
    
    /**
     * Method returning a id of a named Worker
     * 
     * 
     * The worker will only be created upon first call, then it's stored in memory until
     * the flush method is called.
     * 
     * @param workerName the name of a named worker.
     * @param workerConfigHome The home interface of the signer config entity bean
     * @return the id of the signer or 0 if no worker with the name is found.
     */
    public synchronized int getWorkerIdFromName(String workerName, IWorkerConfigDataService workerConfigHome, IGlobalConfigurationSession gCSession, IWorkerManagerSessionLocal workerManagerSession, SignServerContext workerContext) {
        int retval = 0;
        loadWorkers(workerConfigHome, gCSession, workerManagerSession, workerContext);
        if (nameToIdMap.get(workerName) == null) {
            return retval;
        }

        retval = ((Integer) nameToIdMap.get(workerName)).intValue();
        LOG.debug("getSignerIdFromName : returning " + retval);
        return retval;
    }

    /**
     * Method to load all available signers
     */
    private void loadWorkers(IWorkerConfigDataService workerConfigHome, IGlobalConfigurationSession gCSession, IWorkerManagerSessionLocal workerManagerSession, SignServerContext workerContext) {
        if (workerStore == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Loading workers into WorkerFactory.");
            }
            workerStore = new HashMap<Integer, IWorker>();
            nameToIdMap = new HashMap<String, Integer>();

            Collection<Integer> workers = workerManagerSession.getWorkers(GlobalConfiguration.WORKERTYPE_ALL, gCSession);
            GlobalConfiguration gc = gCSession.getGlobalConfiguration();
            Iterator<Integer> iter = workers.iterator();
            while (iter.hasNext()) {
                Integer nextId = (Integer) iter.next();
                final String classpath = gc.getWorkerClassPath(nextId.intValue());
                
                try {
                    
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Loading worker with classpath: " + classpath);
                    }
                    if (classpath != null) {
                        ClassLoader cl = this.getClass().getClassLoader();
                        Class<?> implClass = cl.loadClass(classpath);

                        Object obj = implClass.newInstance();

                        getWorkerStore().put(nextId, (IWorker) obj);

                        WorkerConfig config = workerConfigHome.getWorkerProperties(nextId.intValue());
                        if (config.getProperties().getProperty(PropertiesConstants.NAME) != null) {
                            getNameToIdMap().put(config.getProperties().getProperty(PropertiesConstants.NAME).toUpperCase(), nextId);
                        }
                    }
                } catch (ClassNotFoundException e) {
                    LOG.error("Worker class not found (is the module included in the build?): " + classpath);
                } catch (IllegalAccessException e) {
                    LOG.error("Could not access worker class: " + classpath);
                } catch (InstantiationException e) {
                    LOG.error("Could not instantiate worker class: " + classpath);
                }
            }

            for (Map.Entry<Integer, IWorker> entry : getWorkerStore().entrySet()) {
                initWorker(entry.getValue(), entry.getKey(), gCSession, workerConfigHome, workerManagerSession, workerContext);
            }
        }
    }
    
    private void initWorker(final IWorker worker, final int workerId, final IGlobalConfigurationSession gCSession, final IWorkerConfigDataService workerConfigHome, final IWorkerManagerSessionLocal workerManagerSession, final SignServerContext workerContext) {
        WorkerConfig config = workerConfigHome.getWorkerProperties(workerId);

        final String cryptoTokenName = config.getProperty("CRYPTOTOKEN");
        SignServerContext context = workerContext.newInstance();
        if (cryptoTokenName != null) {
            context.setCryptoTokenSupplier(new CryptoTokenSupplier() {

                @Override
                public ICryptoToken getCurrentCryptoToken() throws SignServerException {
                    synchronized (WorkerFactory.this) {
                        Integer cryptoWorkerId = nameToIdMap.get(cryptoTokenName.toUpperCase());
                        if (cryptoWorkerId != null) {
                            IWorker cryptoWorker = getWorker(cryptoWorkerId, workerConfigHome, gCSession, workerManagerSession, workerContext.newInstance());
                            if (cryptoWorker instanceof BaseProcessable) {
                                return ((BaseProcessable) cryptoWorker).getCryptoToken();
                            } else {
                                return null;
                            }
                        } else {
                            return null;
                        }
                    }
                }
                
            });
            
        }

        worker.init(workerId, config, context, null);
    }

    /**
     * Method used to force reinitialization of all the signers.
     * Should be called from the GlobalConfigurationFileParser.reloadConfiguration() method
     *
     */
    public synchronized void flush() {
        if (workerStore != null) {
            workerStore = null;
            nameToIdMap = null;
            authenticatorStore = null;
            workerLoggerStore = null;
            accounterStore = null;
        }
    }

    /**
     * Method used to force a reload of worker. 
     * @param id of worker
     */
    public synchronized void reloadWorker(int id, IWorkerConfigDataService workerConfigHome, IGlobalConfigurationSession gCSession, IWorkerManagerSessionLocal workerManagerSession, SignServerContext workerContext) {
        if (workerStore == null) {
            workerStore = new HashMap<Integer, IWorker>();
            nameToIdMap = new HashMap<String, Integer>();
        }
        if (authenticatorStore == null) {
            authenticatorStore = new HashMap<Integer, IAuthorizer>();
        }
        if (workerLoggerStore == null) {
            workerLoggerStore = new HashMap<Integer, IWorkerLogger>();
        }
        if (accounterStore == null) {
            accounterStore = new HashMap<Integer, IAccounter>();
        }

        if (id != 0) {
            // Call destroy on old worker
            IWorker oldWorker = workerStore.get(id);
            if (oldWorker instanceof BaseProcessable) {
                ((BaseProcessable) oldWorker).destroy();
            }

            workerStore.put(id, null);
            authenticatorStore.put(id, null);
            workerLoggerStore.put(id, null);
            accounterStore.put(id, null);
            archiversStore.put(id, null);
            Iterator<String> iter = nameToIdMap.keySet().iterator();
            while (iter.hasNext()) {
                String next = (String) iter.next();
                if (nameToIdMap.get(next) != null
                        && ((Integer) nameToIdMap.get(next)).intValue() == id) {
                    iter.remove();
                }
            }
        }
        GlobalConfiguration gc = gCSession.getGlobalConfiguration();

        try {
            String classpath = gc.getWorkerClassPath(id);
            if (classpath != null) {
                WorkerConfig config = workerConfigHome.getWorkerProperties(id);
                ClassLoader cl = this.getClass().getClassLoader();
                Class<?> implClass = cl.loadClass(classpath);

                Object obj = implClass.newInstance();
                if (obj instanceof IProcessable) {
                    if (config.getProperties().getProperty(PropertiesConstants.NAME) != null) {
                        getNameToIdMap().put(config.getProperties().getProperty(PropertiesConstants.NAME).toUpperCase(), new Integer(id));
                    }
                }
                initWorker((IWorker) obj, id, gCSession, workerConfigHome, workerManagerSession, workerContext);
                getWorkerStore().put(new Integer(id), (IWorker) obj);
            }
        } catch (ClassNotFoundException e) {
            LOG.error("Error reloading worker : " + e.getMessage(), e);
        } catch (IllegalAccessException e) {
            LOG.error("Error reloading worker : " + e.getMessage(), e);
        } catch (InstantiationException e) {
            LOG.error("Error reloading worker : " + e.getMessage(), e);
        }
    }

    /**
     * Returns the configured authorizer for the given worker.
     * 
     * @param workerId id of worker 
     * @param authType one of ISigner.AUTHTYPE_ constants or class path to custom implementation
     * @return initialized authorizer.
     */
    public synchronized IAuthorizer getAuthenticator(int workerId, String authType, WorkerConfig config, EntityManager em) throws IllegalRequestException {
        if (getAuthenticatorStore().get(workerId) == null) {
            IAuthorizer auth = null;
            if (authType.equalsIgnoreCase(IProcessable.AUTHTYPE_NOAUTH)) {
                auth = new NoAuthorizer();
            } else if (authType.equalsIgnoreCase(IProcessable.AUTHTYPE_CLIENTCERT)) {
                auth = new ClientCertAuthorizer();
            } else {
                try {
                    Class<?> c = this.getClass().getClassLoader().loadClass(authType);
                    auth = (IAuthorizer) c.newInstance();
                } catch (ClassNotFoundException e) {
                    LOG.error("Error worker with id " + workerId + " misconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.", e);
                    throw new IllegalRequestException("Error worker with id " + workerId + " misconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.");
                } catch (InstantiationException e) {
                    LOG.error("Error worker with id " + workerId + " misconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.", e);
                    throw new IllegalRequestException("Error worker with id " + workerId + " misconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.");
                } catch (IllegalAccessException e) {
                    LOG.error("Error worker with id " + workerId + " misconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.", e);
                    throw new IllegalRequestException("Error worker with id " + workerId + " misconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.");
                }
            }
            
            try {
                auth.init(workerId, config, em);
            } catch (SignServerException e) {
                LOG.error("Error initializing authorizer for worker " + workerId + " with authtype " + authType + ", message : " + e.getMessage(), e);
            }
            getAuthenticatorStore().put(workerId, auth);
        }
        return getAuthenticatorStore().get(workerId);
    }

    public synchronized IWorkerLogger getWorkerLogger(final int workerId,
            final WorkerConfig config, final EntityManager em)
            throws IllegalRequestException {
        IWorkerLogger workerLogger = getWorkerLoggerStore().get(workerId);
        if (workerLogger == null) {
            final String fullClassName = config.getProperty(WORKERLOGGER);

            if (fullClassName == null || "".equals(fullClassName)) {
                workerLogger = new AllFieldsWorkerLogger();
            } else {
                try {
                    final Class<?> c = this.getClass().getClassLoader().loadClass(fullClassName);
                    workerLogger = (IWorkerLogger) c.newInstance();
                } catch (ClassNotFoundException e) {
                    final String error =
                            "Error worker with id " + workerId
                            + " misconfiguration, "
                            + WORKERLOGGER + " setting : "
                            + fullClassName
                            + " is not a correct "
                            + "fully qualified class name "
                            + "of an IWorkerLogger.";
                    LOG.error(error, e);
                    throw new IllegalRequestException(error);
                } catch (InstantiationException e) {
                    final String error =
                            "Error worker with id " + workerId
                            + " misconfiguration, "
                            + WORKERLOGGER + " setting : "
                            + fullClassName
                            + " is not a correct "
                            + "fully qualified class name "
                            + "of an IWorkerLogger.";
                    LOG.error(error, e);
                    throw new IllegalRequestException(error);

                } catch (IllegalAccessException e) {
                    final String error =
                            "Error worker with id " + workerId
                            + " misconfiguration, "
                            + WORKERLOGGER + " setting : "
                            + fullClassName
                            + " is not a correct "
                            + "fully qualified class name "
                            + "of an IWorkerLogger.";
                    LOG.error(error, e);
                    throw new IllegalRequestException(error);
                }
            }
            workerLogger.init(config.getProperties());
            getWorkerLoggerStore().put(workerId, workerLogger);
        }
//            return workerLogger;
        return getWorkerLoggerStore().get(workerId);
    }

    public synchronized IAccounter getAccounter(final int workerId,
            final WorkerConfig config, final EntityManager em)
            throws IllegalRequestException {
        IAccounter accounter = getAccounterStore().get(workerId);
        if (accounter == null) {
            final String fullClassName = config.getProperty(ACCOUNTER);

            if (fullClassName == null || "".equals(fullClassName)) {
                accounter = new NoAccounter();
            } else {
                try {
                    final Class<?> c = this.getClass().getClassLoader().loadClass(fullClassName);
                    accounter = (IAccounter) c.newInstance();
                } catch (ClassNotFoundException e) {
                    final String error =
                            "Error worker with id " + workerId
                            + " misconfiguration, "
                            + ACCOUNTER + " setting : "
                            + fullClassName
                            + " is not a correct "
                            + "fully qualified class name "
                            + "of an IAccounter.";
                    LOG.error(error, e);
                    throw new IllegalRequestException(error);
                } catch (InstantiationException e) {
                    final String error =
                            "Error worker with id " + workerId
                            + " misconfiguration, "
                            + ACCOUNTER + " setting : "
                            + fullClassName
                            + " is not a correct "
                            + "fully qualified class name "
                            + "of an IAccounter.";
                    LOG.error(error, e);
                    throw new IllegalRequestException(error);

                } catch (IllegalAccessException e) {
                    final String error =
                            "Error worker with id " + workerId
                            + " misconfiguration, "
                            + ACCOUNTER + " setting : "
                            + fullClassName
                            + " is not a correct "
                            + "fully qualified class name "
                            + "of an IAccounter.";
                    LOG.error(error, e);
                    throw new IllegalRequestException(error);
                }
            }
            accounter.init(config.getProperties());
            getAccounterStore().put(workerId, accounter);
        }
        return getAccounterStore().get(workerId);
    }

    public synchronized List<Archiver> getArchivers(final int workerId,
            final WorkerConfig config, final SignServerContext context)
            throws IllegalRequestException {
        List<Archiver> archivers = getArchiversStore().get(workerId);
        if (archivers == null) {
            archivers = new LinkedList<Archiver>();
            final String list;

            // Support for old way of setting archiving and the new one
            if (config.getProperty(SignServerConstants.ARCHIVE,
                    Boolean.FALSE.toString()).equalsIgnoreCase(Boolean.TRUE.toString())) {
                list = OldDatabaseArchiver.class.getName();
            } else {
                list = config.getProperty(SignServerConstants.ARCHIVERS);
            }

            if (list != null) {
                int index = 0;
                for (String className : list.split(",")) {
                    className = className.trim();

                    if (!className.isEmpty()) {
                        try {
                            final Class<?> c = this.getClass().getClassLoader().loadClass(className);
                            final Archiver archiver = (Archiver) c.newInstance();
                            archivers.add(archiver);
                            try {
                                archiver.init(index, config, context);
                            } catch (ArchiverInitException e) {
                                final String error =
                                        "Error worker with id " + workerId
                                        + " misconfiguration, "
                                        + "failed to initialize archiver "
                                        + index + ".";
                                LOG.error(error, e);
                                throw new IllegalRequestException(error);
                            }
                            index++;
                        } catch (ClassNotFoundException e) {
                            final String error =
                                    "Error worker with id " + workerId
                                    + " misconfiguration, "
                                    + SignServerConstants.ARCHIVERS
                                    + " setting : "
                                    + className
                                    + " is not a correct "
                                    + "fully qualified class name "
                                    + "of an Archiver.";
                            LOG.error(error, e);
                            throw new IllegalRequestException(error);
                        } catch (InstantiationException e) {
                            final String error =
                                    "Error worker with id " + workerId
                                    + " misconfiguration, "
                                    + SignServerConstants.ARCHIVERS
                                    + " setting : "
                                    + className
                                    + " is not a correct "
                                    + "fully qualified class name "
                                    + "of an Archiver.";
                            LOG.error(error, e);
                            throw new IllegalRequestException(error);

                        } catch (IllegalAccessException e) {
                            final String error =
                                    "Error worker with id " + workerId
                                    + " misconfiguration, "
                                    + SignServerConstants.ARCHIVERS
                                    + " setting : "
                                    + className
                                    + " is not a correct "
                                    + "fully qualified class name "
                                    + "of an Archiver.";
                            LOG.error(error, e);
                            throw new IllegalRequestException(error);
                        }
                    }
                    getArchiversStore().put(workerId, archivers);
                }
            }
        }
        return getArchiversStore().get(workerId);  // TODO: just return archivers!
    }

    private Map<String, Integer> getNameToIdMap() {
        if (nameToIdMap == null) {
            nameToIdMap = new HashMap<String, Integer>();
        }
        return nameToIdMap;
    }

    private Map<Integer, IWorker> getWorkerStore() {
        if (workerStore == null) {
            workerStore = new HashMap<Integer, IWorker>();
        }
        return workerStore;
    }

    private Map<Integer, IAuthorizer> getAuthenticatorStore() {
        if (authenticatorStore == null) {
            authenticatorStore = new HashMap<Integer, IAuthorizer>();
        }
        return authenticatorStore;
    }

    private Map<Integer, IWorkerLogger> getWorkerLoggerStore() {
        if (workerLoggerStore == null) {
            workerLoggerStore = new HashMap<Integer, IWorkerLogger>();
        }
        return workerLoggerStore;
    }

    private Map<Integer, IAccounter> getAccounterStore() {
        if (accounterStore == null) {
            accounterStore = new HashMap<Integer, IAccounter>();
        }
        return accounterStore;
    }

    private Map<Integer, List<Archiver>> getArchiversStore() {
        return archiversStore;
    }
}
