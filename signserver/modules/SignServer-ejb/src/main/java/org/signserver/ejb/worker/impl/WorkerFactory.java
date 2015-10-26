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
import org.signserver.server.*;
import org.signserver.server.archive.Archiver;
import org.signserver.server.archive.ArchiverInitException;
import org.signserver.server.archive.olddbarchiver.OldDatabaseArchiver;
import org.signserver.server.config.entities.IWorkerConfigDataService;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.log.AllFieldsWorkerLogger;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.signers.NoImplementationWorker;

/**
 * Loads worker configurations and instantiates the implementations and caches
 * those.
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

    private Map<Integer, IWorker> workerStore = new HashMap<>();
    private Map<Integer, IAuthorizer> authenticatorStore = new HashMap<>();
    private Map<Integer, IWorkerLogger> workerLoggerStore = new HashMap<>();
    private Map<Integer, IAccounter> accounterStore = new HashMap<>();
    private final Map<Integer, List<Archiver>> archiversStore  = new HashMap<>();

    private Map<String, Integer> nameToIdMap = new HashMap<>();

    private final IWorkerConfigDataService workerConfigHome;
    private final SignServerContext workerContext;

    protected WorkerFactory(IWorkerConfigDataService workerConfigHome, SignServerContext workerContext) {
        this.workerConfigHome = workerConfigHome;
        this.workerContext = workerContext;
    }

    /**
     * Method returning a worker given it's id. The signer should be defined in
     * the global configuration along with it's id.
     *
     * The worker will only be created upon first call, then it's stored in memory until
     * the flush method is called.
     *
     * @param workerId the Id that should match the one in the config file.
     * @return A ISigner as defined in the configuration file, or null if no configuration
     * for the specified signerId could be found.
     * @throws NoSuchWorkerException In case the worker ID does not exist
     */
    public synchronized IWorker getWorker(int workerId) throws NoSuchWorkerException {
        IWorker result = workerStore.get(workerId);
        if (result == null) {
            loadWorker(workerId);
        }
        result = workerStore.get(workerId);
        if (result == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Trying to get worker with Id that does not exist: " + workerId);
            }
            throw new NoSuchWorkerException(String.valueOf(workerId));
        }
        return result;
    }

    /**
     * Method returning a id of a named Worker
     *
     *
     * The worker will only be created upon first call, then it's stored in memory until
     * the flush method is called.
     *
     * @param workerName the name of a named worker.
     * @return the id of the worker
     * @throws NoSuchWorkerException in case a worker with the name does not exist
     */
    public synchronized int getWorkerIdFromName(final String workerName) throws NoSuchWorkerException {
        if (LOG.isDebugEnabled()) {
            LOG.debug(">getWorkerIdFromName(" + workerName + ")");
        }
        if (workerName == null) {
            throw new NullPointerException("workerName is null");
        }
        Integer result = nameToIdMap.get(workerName.toUpperCase());
        if (result == null) {
            result = workerConfigHome.findId(workerName);
            nameToIdMap.put(workerName.toUpperCase(), result);
        }
        return result;
    }

    private void loadWorker(int workerId) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Loading worker into WorkerFactory: " + workerId);
        }
        WorkerConfig config = workerConfigHome.getWorkerProperties(workerId, false);
        if (config != null) {
            final String classpath = config.getImplementationClass();

            try {

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Loading worker with classpath: " + classpath);
                }

                // XXX: This is duplicated
                final IWorker worker;
                if (classpath == null) {
                    worker = new NoImplementationWorker();
                } else {
                    ClassLoader cl = this.getClass().getClassLoader();
                    Class<?> implClass = cl.loadClass(classpath);

                    worker = (IWorker) implClass.newInstance();
                }
                workerStore.put(workerId, worker);

                if (config.getProperties().getProperty(PropertiesConstants.NAME) != null) {
                    nameToIdMap.put(config.getProperties().getProperty(PropertiesConstants.NAME).toUpperCase(), workerId);
                }

                initWorker(worker, workerId, config);
            } catch (ClassNotFoundException e) {
                LOG.error("Worker class not found (is the module included in the build?): " + classpath);
            } catch (IllegalAccessException e) {
                LOG.error("Could not access worker class: " + classpath);
            } catch (InstantiationException e) {
                LOG.error("Could not instantiate worker class: " + classpath);
            }
        }
    }

    private void initWorker(final IWorker worker, final int workerId, final WorkerConfig config) {
        final String cryptoTokenName = config.getProperty("CRYPTOTOKEN");
        SignServerContext context = workerContext.newInstance();
        if (cryptoTokenName != null) {
            context.setCryptoTokenSupplier(new CryptoTokenSupplier() {

                @Override
                public ICryptoToken getCurrentCryptoToken() throws SignServerException {
                    synchronized (WorkerFactory.this) {
                        try {
                            IWorker cryptoWorker = getWorker(getWorkerIdFromName(cryptoTokenName));
                            if (cryptoWorker instanceof BaseProcessable) {
                                return ((BaseProcessable) cryptoWorker).getCryptoToken();
                            } else {
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("Not a processable worker: " + cryptoWorker);
                                }
                                return null;
                            }
                        } catch (NoSuchWorkerException ex) {
                            LOG.info("Unable to get crypto worker: " + cryptoTokenName);
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
        workerStore = new HashMap<>();
        nameToIdMap = new HashMap<>();
        authenticatorStore = new HashMap<>();
        workerLoggerStore = new HashMap<>();
        accounterStore = new HashMap<>();
    }

    /**
     * Method used to force a reload of worker.
     * @param id of worker
     */
    public synchronized void reloadWorker(int id) {
        if (id != 0) {
            workerStore.remove(id);
            authenticatorStore.remove(id);
            workerLoggerStore.remove(id);
            accounterStore.remove(id);
            archiversStore.remove(id);

            Iterator<String> iter = nameToIdMap.keySet().iterator();

            while (iter.hasNext()) {
                String next = iter.next();
                if (nameToIdMap.get(next) == null || nameToIdMap.get(next) == id) {
                    iter.remove();
                }
            }
        }

        try {
            WorkerConfig config = workerConfigHome.getWorkerProperties(id, false);
            if (config != null) {
                String className = config.getImplementationClass();

                // XXX: This is duplicated
                final IWorker worker;
                if (className == null) {
                    worker = new NoImplementationWorker();
                } else {
                    ClassLoader cl = this.getClass().getClassLoader();
                    Class<?> implClass = cl.loadClass(className);

                    worker = (IWorker) implClass.newInstance();
                }
                workerStore.put(id, worker);

                if (config.getProperties().getProperty(PropertiesConstants.NAME) != null) {
                    nameToIdMap.put(config.getProperties().getProperty(PropertiesConstants.NAME).toUpperCase(), id);
                }

                initWorker(worker, id, config);
            }
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
            LOG.error("Error reloading worker : " + e.getMessage(), e);
        }
    }

    /**
     * Returns the configured authorizer for the given worker.
     *
     * @param workerId id of worker
     * @param authType one of ISigner.AUTHTYPE_ constants or class path to custom implementation
     * @param config the worker config
     * @param em EntityManager to provide
     * @return initialized authorizer.
     * @throws SignServerException
     */
    public synchronized IAuthorizer getAuthenticator(int workerId, String authType, WorkerConfig config, EntityManager em)
            throws SignServerException {
        if (authenticatorStore.get(workerId) == null) {
            IAuthorizer auth = null;
            if (authType.equalsIgnoreCase(IProcessable.AUTHTYPE_NOAUTH)) {
                auth = new NoAuthorizer();
            } else if (authType.equalsIgnoreCase(IProcessable.AUTHTYPE_CLIENTCERT)) {
                auth = new ClientCertAuthorizer();
            } else {
                try {
                    Class<?> c = this.getClass().getClassLoader().loadClass(authType);
                    auth = (IAuthorizer) c.newInstance();
                } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                    LOG.error("Error worker with id " + workerId + " misconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.", e);
                    throw new SignServerException("Error worker with id " + workerId + " misconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.");
                }
            }

            try {
                auth.init(workerId, config, em);
            } catch (SignServerException e) {
                LOG.error("Error initializing authorizer for worker " + workerId + " with authtype " + authType + ", message : " + e.getMessage(), e);
            }
            authenticatorStore.put(workerId, auth);
        }
        return authenticatorStore.get(workerId);
    }

    public synchronized IWorkerLogger getWorkerLogger(final int workerId,
            final WorkerConfig config, final EntityManager em)
            throws SignServerException {
        IWorkerLogger workerLogger = workerLoggerStore.get(workerId);
        if (workerLogger == null) {
            final String fullClassName = config.getProperty(WORKERLOGGER);

            if (fullClassName == null || "".equals(fullClassName)) {
                workerLogger = new AllFieldsWorkerLogger();
            } else {
                try {
                    final Class<?> c = this.getClass().getClassLoader().loadClass(fullClassName);
                    workerLogger = (IWorkerLogger) c.newInstance();
                } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                    final String error =
                            "Error worker with id " + workerId
                            + " misconfiguration, "
                            + WORKERLOGGER + " setting : "
                            + fullClassName
                            + " is not a correct "
                            + "fully qualified class name "
                            + "of an IWorkerLogger.";
                    LOG.error(error, e);
                    throw new SignServerException(error);
                }
            }
            workerLogger.init(config.getProperties());
            workerLoggerStore.put(workerId, workerLogger);
        }
        return workerLoggerStore.get(workerId);
    }

    public synchronized IAccounter getAccounter(final int workerId,
            final WorkerConfig config, final EntityManager em)
            throws SignServerException {
        IAccounter accounter = accounterStore.get(workerId);
        if (accounter == null) {
            final String fullClassName = config.getProperty(ACCOUNTER);

            if (fullClassName == null || "".equals(fullClassName)) {
                accounter = new NoAccounter();
            } else {
                try {
                    final Class<?> c = this.getClass().getClassLoader().loadClass(fullClassName);
                    accounter = (IAccounter) c.newInstance();
                } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                    final String error =
                            "Error worker with id " + workerId
                            + " misconfiguration, "
                            + ACCOUNTER + " setting : "
                            + fullClassName
                            + " is not a correct "
                            + "fully qualified class name "
                            + "of an IAccounter.";
                    LOG.error(error, e);
                    throw new SignServerException(error);
                }
            }
            accounter.init(config.getProperties());
            accounterStore.put(workerId, accounter);
        }
        return accounterStore.get(workerId);
    }

    public synchronized List<Archiver> getArchivers(final int workerId,
            final WorkerConfig config, final SignServerContext context)
            throws SignServerException {
        List<Archiver> archivers = archiversStore.get(workerId);
        if (archivers == null) {
            archivers = new LinkedList<>();
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
                                throw new SignServerException(error);
                            }
                            index++;
                        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
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
                            throw new SignServerException(error);
                        }
                    }
                    archiversStore.put(workerId, archivers);
                }
            }
        }
        return archiversStore.get(workerId);  // TODO: just return archivers!
    }

    public synchronized Collection<Integer> getCachedWorkerIds() {
        return workerStore.keySet();
    }

}
