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
package org.signserver.server;

import java.lang.reflect.Constructor;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.SignServerConstants;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.server.archive.Archiver;
import org.signserver.server.archive.ArchiverInitException;
import org.signserver.server.archive.olddbarchiver.OldDatabaseArchiver;
import org.signserver.server.clusterclassloader.IEntityManagerSupport;
import org.signserver.server.log.AllFieldsWorkerLogger;
import org.signserver.server.log.IWorkerLogger;

/**
 * Class used to manage different signers used in the system, uses the configuration in
 * GlobalConfigurationFileParser as a backup.
 * 
 * XXX: Large scary singleton. Consider re-design.
 * FIXME: A lot of "Synchronization on non-final field"
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class WorkerFactory {

    /** Logger for this class. */
    public static final Logger LOG = Logger.getLogger(WorkerFactory.class);
    
    private static final String WORKERLOGGER = "WORKERLOGGER";
    
    private static final String ACCOUNTER = "ACCOUNTER";
    
    private static WorkerFactory instance = new WorkerFactory();

    private WorkerFactory() {
    }

    public static WorkerFactory getInstance() {
        return instance;
    }
    
    private Map<Integer, IWorker> workerStore;
    
    private Map<Integer, IAuthorizer> authenticatorStore;
    
    private Map<String, Integer> nameToIdMap;
    
    private Map<Integer, ClassLoader> workerClassLoaderMap;
    
    private Map<Integer, IWorkerLogger> workerLoggerStore;
    
    private Map<Integer, IAccounter> accounterStore;
    
    private final Map<Integer, List<Archiver>> archiversStore 
            = Collections.synchronizedMap(new HashMap<Integer, List<Archiver>>());

    /**
     * Method returning a worker given it's id. The signer should be defined in 
     * the global configuration along with it's id.
     * 
     * The worker will only be created upon first call, then it's stored in memory until
     * the flush method is called.
     * 
     * @param signerId the Id that should match the one in the config file.
     * @param workerConfigHome The service interface of the signer config entity bean
     * @param mailSignerContext 
     * @return A ISigner as defined in the configuration file, or null if no configuration
     * for the specified signerId could be found.
     */
    public IWorker getWorker(int workerId, 
            IWorkerConfigDataService workerConfigHome, 
            IGlobalConfigurationSession gCSession, 
            WorkerContext workerContext) {
        Integer id = new Integer(workerId);

        loadWorkers(workerConfigHome, gCSession, workerContext);
        synchronized (workerStore) {
            IWorker ret = (IWorker) workerStore.get(id);
            if (ret == null) {
                LOG.info("Trying to get worker with Id that does not exist: " + workerId);
            }
            return ret;
        }

    }

    /**
     * Method returning a signer given it's name. The signers NAME should be defined in 
     * the signers configuration as the property NAME.
     * 
     * 
     * The worker will only be created upon first call, then it's stored in memory until
     * the flush method is called.
     * 
     * @param workerName the name that should match the one in the config file.
     * @param workerConfigHome The home interface of the signer config entity bean
     * @return A ISigner as defined in the configuration file, or null if no configuration
     * for the specified signerId could be found.
     */
    /*
    public IProcessable getProcessable(String workerName, IWorkerConfigDataService workerConfigHome, IGlobalConfigurationSession.ILocal gCSession, EntityManager em, WorkerContext workerContext){	   
    IProcessable retval = null;
    
    loadWorkers(workerConfigHome,gCSession,em, workerContext);
    
    synchronized(nameToIdMap){	
    synchronized(workerStore){
    if(nameToIdMap.get(workerName) != null){
    retval = (IProcessable) workerStore.get(nameToIdMap.get(workerName));
    }
    }
    }
    
    return retval;
    }*/
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
    public int getWorkerIdFromName(String workerName, IWorkerConfigDataService workerConfigHome, IGlobalConfigurationSession gCSession, WorkerContext workerContext) {
        int retval = 0;
        loadWorkers(workerConfigHome, gCSession, workerContext);
        synchronized (nameToIdMap) {
            synchronized (workerStore) {
                if (nameToIdMap.get(workerName) == null) {
                    return retval;
                }

                retval = ((Integer) nameToIdMap.get(workerName)).intValue();
            }
        }
        LOG.debug("getSignerIdFromName : returning " + retval);
        return retval;
    }

    /**
     * Method to load all available signers
     */
    private synchronized void loadWorkers(IWorkerConfigDataService workerConfigHome, IGlobalConfigurationSession gCSession, WorkerContext workerContext) {
        if (workerStore == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Loading workers into WorkerFactory.");
            }
            workerStore = new HashMap<Integer, IWorker>();
            nameToIdMap = new HashMap<String, Integer>();
            workerClassLoaderMap = new HashMap<Integer, ClassLoader>();

            Collection<Integer> workers = gCSession.getWorkers(GlobalConfiguration.WORKERTYPE_ALL);
            GlobalConfiguration gc = gCSession.getGlobalConfiguration();
            Iterator<Integer> iter = workers.iterator();
            while (iter.hasNext()) {
                Integer nextId = (Integer) iter.next();
                try {
                    String classpath = gc.getWorkerClassPath(nextId.intValue());
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Loading worker with classpath: " + classpath);
                    }
                    if (classpath != null) {
                        WorkerConfig config = workerConfigHome.getWorkerProperties(nextId.intValue());

                        EntityManager em = null;
                        if (workerContext instanceof SignServerContext) {
                            em = ((SignServerContext) workerContext).getEntityManager();
                        }
                        ClassLoader cl = getClassLoader(em, nextId, config);
                        Class<?> implClass = cl.loadClass(classpath);

                        Object obj = implClass.newInstance();

                        if (obj instanceof IProcessable || obj.getClass().getSimpleName().equals("IMailProcessor")) {
                            config = workerConfigHome.getWorkerProperties(nextId.intValue());
                            if (config.getProperties().getProperty(ProcessableConfig.NAME) != null) {
                                getNameToIdMap().put(config.getProperties().getProperty(ProcessableConfig.NAME).toUpperCase(), nextId);
                            }
                        }

                        if (getClassLoader(em, nextId.intValue(), config) instanceof IEntityManagerSupport) {
                            ((IWorker) obj).init(nextId.intValue(), config, workerContext, ((IEntityManagerSupport) getClassLoader(em, nextId, config)).getWorkerEntityManger(config));
                        } else {
                            ((IWorker) obj).init(nextId.intValue(), config, workerContext, null);
                        }
                        getWorkerStore().put(nextId, (IWorker) obj);
                    }
                } catch (ClassNotFoundException e) {
                    LOG.error("Error loading workers : " + e.getMessage(), e);
                } catch (IllegalAccessException e) {
                    LOG.error("Error loading workers : " + e.getMessage(), e);
                } catch (InstantiationException e) {
                    LOG.error("Error loading workers : " + e.getMessage(), e);
                }
            }
        }
    }

    /**
     * Method that manages all available class loaders in the system.
     * 
     * It looks up the version used in the worker configuration by the 
     * properties MODULENAME, and MODULEVERSION, the the setting doesn't exist will
     * the latest available version be used.
     * 
     * If MODULENAME isn't specified will the default app server
     * class loader be used.
     * 
     * @param config the worker configuration
     * @return the class loader specific for the given worker.
     */
    public ClassLoader getClassLoader(EntityManager em, int workerId, WorkerConfig config) {
        ClassLoader retval = workerClassLoaderMap.get(workerId);
        if (retval == null) {
            retval = this.getClass().getClassLoader();
            String moduleName = config.getProperty(SignServerConstants.MODULENAME);
            if (GlobalConfiguration.isClusterClassLoaderEnabled() && config.getProperty("MODULENAME") != null) {
                Integer moduleVersion = null;
                try {
                    if (config.getProperty(SignServerConstants.MODULEVERSION) != null) {
                        moduleVersion = Integer.parseInt(config.getProperty(SignServerConstants.MODULEVERSION));
                    }
                } catch (NumberFormatException e) {
                    LOG.error("Error: Worker with id " + workerId + " is missconfigured property " + SignServerConstants.MODULEVERSION + " should only contain digits but has the value "
                            + config.getProperty(SignServerConstants.MODULEVERSION));
                }

                // Create ExtendedClusterClassLoader by 
                // reflection as we don't want to have a 
                // dependency on it if it is not going to be 
                // used.
                retval = createExtendedClusterClassLoader(this.getClass().getClassLoader(),
                        em, moduleName, "server", moduleVersion);
            }

            workerClassLoaderMap.put(workerId, retval);

        }
        return retval;
    }

    private ClassLoader createExtendedClusterClassLoader(
            final ClassLoader parent, final EntityManager em,
            final String moduleName, final String part,
            final Integer version) {
        try {
            final Class<? extends ClassLoader> t = (Class<? extends ClassLoader>) Class.forName(
                    "org.signserver.server.clusterclassloader.ExtendedClusterClassLoader");

            final Class[] ctorTypes;
            final Object[] args;

            if (version == null) {
                ctorTypes = new Class[]{
                    ClassLoader.class, EntityManager.class, String.class,
                    String.class
                };
                args = new Object[]{parent, em, moduleName, part};
            } else {
                ctorTypes = new Class[]{
                    ClassLoader.class, EntityManager.class, String.class,
                    String.class, Integer.TYPE
                };
                args = new Object[]{parent, em, moduleName, part,
                    version};
            }

            final Constructor<? extends ClassLoader> ctor = t.getConstructor(ctorTypes);
            return ctor.newInstance(args);
        } catch (Throwable ex) {
            throw new RuntimeException("Could not construct "
                    + "ExtendedClusterClassLoader", ex);
        }
    }

    /**
     * Method used to force reinitialization of all the signers.
     * Should be called from the GlobalConfigurationFileParser.reloadConfiguration() method
     *
     */
    public void flush() {
        if (workerStore != null) {
            workerStore = null;
            nameToIdMap = null;
            authenticatorStore = null;
            workerClassLoaderMap = null;
            workerLoggerStore = null;
            accounterStore = null;
        }
    }

    /**
     * Method used to force a reload of worker. 
     * @param id of worker
     */
    public void reloadWorker(int id, IWorkerConfigDataService workerConfigHome, IGlobalConfigurationSession gCSession, WorkerContext workerContext) {

        if (workerStore == null) {
            workerStore = Collections.synchronizedMap(new HashMap<Integer, IWorker>());
            nameToIdMap = Collections.synchronizedMap(new HashMap<String, Integer>());

        }

        if (authenticatorStore == null) {
            authenticatorStore = Collections.synchronizedMap(new HashMap<Integer, IAuthorizer>());
        }

        if (workerClassLoaderMap == null) {
            workerClassLoaderMap = Collections.synchronizedMap(new HashMap<Integer, ClassLoader>());
        }

        if (workerLoggerStore == null) {
            workerLoggerStore = Collections.synchronizedMap(new HashMap<Integer, IWorkerLogger>());
        }

        if (accounterStore == null) {
            accounterStore = Collections.synchronizedMap(new HashMap<Integer, IAccounter>());
        }

        synchronized (nameToIdMap) {
            synchronized (workerStore) {
                synchronized (authenticatorStore) {
                    synchronized (workerClassLoaderMap) {
                        synchronized (workerLoggerStore) {
                            synchronized (accounterStore) {
                                synchronized (archiversStore) {
                                    if (id != 0) {

                                        // Call destroy on old worker
                                        IWorker oldWorker = workerStore.get(id);
                                        if (oldWorker instanceof BaseProcessable) {
                                            ((BaseProcessable) oldWorker).destroy();
                                        }

                                        workerStore.put(id, null);
                                        authenticatorStore.put(id, null);
                                        workerClassLoaderMap.put(id, null);
                                        workerLoggerStore.put(id,
                                                null);
                                        accounterStore.put(
                                                id,
                                                null);
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
                                            EntityManager em = null;
                                            if (workerContext instanceof SignServerContext) {
                                                em = ((SignServerContext) workerContext).getEntityManager();
                                            }
                                            ClassLoader cl = getClassLoader(em, id, config);
                                            Class<?> implClass = cl.loadClass(classpath);

                                            Object obj = implClass.newInstance();

                                            if (obj instanceof IProcessable || obj.getClass().getSimpleName().equals("IMailProcessor")) {
                                                if (config.getProperties().getProperty(ProcessableConfig.NAME) != null) {
                                                    getNameToIdMap().put(config.getProperties().getProperty(ProcessableConfig.NAME).toUpperCase(), new Integer(id));
                                                }
                                            }

                                            if (getClassLoader(em, id, config) instanceof IEntityManagerSupport) {
                                                ((IWorker) obj).init(id, config, workerContext, ((IEntityManagerSupport) getClassLoader(em, id, config)).getWorkerEntityManger(config));
                                            } else {
                                                ((IWorker) obj).init(id, config, workerContext, null);
                                            }
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
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Returns the configured authorizer for the given worker.
     * 
     * @param workerId id of worker 
     * @param authType one of ISigner.AUTHTYPE_ constants or class path to custom implementation
     * @return initialized authorizer.
     */
    public IAuthorizer getAuthenticator(int workerId, String authType, WorkerConfig config, EntityManager em) throws IllegalRequestException {
        if (getAuthenticatorStore().get(workerId) == null) {
            IAuthorizer auth = null;
            if (authType.equalsIgnoreCase(IProcessable.AUTHTYPE_NOAUTH)) {
                auth = new NoAuthorizer();
            } else if (authType.equalsIgnoreCase(IProcessable.AUTHTYPE_CLIENTCERT)) {
                auth = new ClientCertAuthorizer();
            } else {

                try {
                    Class<?> c = getClassLoader(em, workerId, config).loadClass(authType);
                    auth = (IAuthorizer) c.newInstance();
                } catch (ClassNotFoundException e) {
                    LOG.error("Error worker with id " + workerId + " missconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.", e);
                    throw new IllegalRequestException("Error worker with id " + workerId + " missconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.");
                } catch (InstantiationException e) {
                    LOG.error("Error worker with id " + workerId + " missconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.", e);
                    throw new IllegalRequestException("Error worker with id " + workerId + " missconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.");
                } catch (IllegalAccessException e) {
                    LOG.error("Error worker with id " + workerId + " missconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.", e);
                    throw new IllegalRequestException("Error worker with id " + workerId + " missconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.");
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

    public IWorkerLogger getWorkerLogger(final int workerId,
            final WorkerConfig config, final EntityManager em)
            throws IllegalRequestException {
        IWorkerLogger workerLogger = getWorkerLoggerStore().get(workerId);
        if (workerLogger == null) {
            final String fullClassName =
                    config.getProperty(WORKERLOGGER);

            if (fullClassName == null || "".equals(fullClassName)) {
                workerLogger = new AllFieldsWorkerLogger();
            } else {
                try {
                    final Class<?> c = getClassLoader(em, workerId,
                            config).loadClass(fullClassName);
                    workerLogger = (IWorkerLogger) c.newInstance();
                } catch (ClassNotFoundException e) {
                    final String error =
                            "Error worker with id " + workerId
                            + " missconfiguration, "
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
                            + " missconfiguration, "
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
                            + " missconfiguration, "
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

    public IAccounter getAccounter(final int workerId,
            final WorkerConfig config, final EntityManager em)
            throws IllegalRequestException {
        IAccounter accounter = getAccounterStore().get(workerId);
        if (accounter == null) {
            final String fullClassName =
                    config.getProperty(ACCOUNTER);

            if (fullClassName == null || "".equals(fullClassName)) {
                accounter = new NoAccounter();
            } else {
                try {
                    final Class<?> c = getClassLoader(em, workerId,
                            config).loadClass(fullClassName);
                    accounter = (IAccounter) c.newInstance();
                } catch (ClassNotFoundException e) {
                    final String error =
                            "Error worker with id " + workerId
                            + " missconfiguration, "
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
                            + " missconfiguration, "
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
                            + " missconfiguration, "
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

    public List<Archiver> getArchivers(final int workerId,
            final WorkerConfig config, final EntityManager em)
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
                SignServerContext context = new SignServerContext(em);
                for (String className : list.split(",")) {
                    className = className.trim();

                    if (!className.isEmpty()) {
                        try {
                            final Class<?> c = getClassLoader(em, workerId,
                                    config).loadClass(className);
                            final Archiver archiver = (Archiver) c.newInstance();
                            archivers.add(archiver);
                            try {
                                archiver.init(index, config, context);
                            } catch (ArchiverInitException e) {
                                final String error =
                                        "Error worker with id " + workerId
                                        + " missconfiguration, "
                                        + "failed to initialize archiver "
                                        + index + ".";
                                LOG.error(error, e);
                                throw new IllegalRequestException(error);
                            }
                            index++;
                        } catch (ClassNotFoundException e) {
                            final String error =
                                    "Error worker with id " + workerId
                                    + " missconfiguration, "
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
                                    + " missconfiguration, "
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
                                    + " missconfiguration, "
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
        return getArchiversStore().get(workerId);
    }

    private Map<String, Integer> getNameToIdMap() {
        if (nameToIdMap == null) {
            nameToIdMap = Collections.synchronizedMap(new HashMap<String, Integer>());
        }
        return nameToIdMap;

    }

    private Map<Integer, IWorker> getWorkerStore() {
        if (workerStore == null) {
            workerStore = Collections.synchronizedMap(new HashMap<Integer, IWorker>());
        }
        return workerStore;

    }

    private Map<Integer, IAuthorizer> getAuthenticatorStore() {
        if (authenticatorStore == null) {
            authenticatorStore = Collections.synchronizedMap(new HashMap<Integer, IAuthorizer>());
        }
        return authenticatorStore;

    }

    private Map<Integer, IWorkerLogger> getWorkerLoggerStore() {
        if (workerLoggerStore == null) {
            workerLoggerStore = Collections.synchronizedMap(new HashMap<Integer, IWorkerLogger>());
        }
        return workerLoggerStore;

    }

    private Map<Integer, IAccounter> getAccounterStore() {
        if (accounterStore == null) {
            accounterStore = Collections.synchronizedMap(new HashMap<Integer, IAccounter>());
        }
        return accounterStore;
    }

    private Map<Integer, List<Archiver>> getArchiversStore() {
        return archiversStore;
    }
}
