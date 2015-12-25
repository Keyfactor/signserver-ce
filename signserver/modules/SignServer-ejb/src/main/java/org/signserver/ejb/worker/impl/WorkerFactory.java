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
import org.signserver.common.WorkerIdentifier;
import org.signserver.server.*;
import org.signserver.server.archive.Archiver;
import org.signserver.server.archive.ArchiverInitException;
import org.signserver.server.archive.olddbarchiver.OldDatabaseArchiver;
import org.signserver.server.config.entities.IWorkerConfigDataService;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.log.AllFieldsWorkerLogger;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.signers.UnloadableWorker;

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

    private final IWorkerConfigDataService workerConfigHome;
    private final SignServerContext workerContext;

    private final WorkerStore cache = new WorkerStore();

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
     * @param wi the Id that should match the one in the config file.
     * @return A ISigner as defined in the configuration file, or null if no configuration
     * for the specified signerId could be found.
     * @throws NoSuchWorkerException In case the worker ID does not exist
     */
    public synchronized IWorker getWorker(WorkerIdentifier wi) throws NoSuchWorkerException {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getWorker(" + wi + ")");
        }
        IWorker result = cache.getWorkerOnly(wi);
        if (result == null) {
            result = loadWorker(wi);
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("getWorker(" + wi + ") returning instance: " + result);
        }
        return result;
    }
    
    /*public synchronized IWorker getWorker(WorkerIdentity worker) throws NoSuchWorkerException {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getWorker(\"" + workerName + "\")");
        }
        IWorker result = cache.getWorkerOnly(workerName);
        if (result == null) {
            result = loadWorker(workerName);
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("getWorker(\"" + workerName + "\") returning instance: " + result);
        }
        return result;
    }*/

    public synchronized WorkerWithComponents getWorkerWithComponents(final WorkerIdentifier wi, final SignServerContext context) throws NoSuchWorkerException {
        WorkerWithComponents result = cache.getWorkerWithComponents(wi);
        if (result == null) {
            result = loadWorkerWithComponents(wi, context);
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("getWorkerWithComponents(" + wi + ") returning instance: " + result + " containing " + result.getWorker());
        }
        return result;
    }
    
    /*public synchronized WorkerWithComponents getWorkerWithComponents(final String workerName, final SignServerContext context) throws NoSuchWorkerException {
        WorkerWithComponents result = cache.getWorkerWithComponents(workerName);
        if (result == null) {
            result = loadWorkerWithComponents(workerName, context);
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("getWorkerWithComponents(" + workerName + ") returning instance: " + result + " containing " + result.getWorker());
        }
        return result;
    }*/
    
    private IWorker loadWorker(final WorkerIdentifier wi) throws NoSuchWorkerException {
        final int workerId;
        if (wi.hasId()) {
            workerId = wi.getId();
        } else {
            workerId = workerConfigHome.findId(wi.getName());
        }

        // Load worker from database
        IWorker result;
        WorkerConfig config = workerConfigHome.getWorkerProperties(workerId, false);
        final String className = config.getImplementationClass();
        if (config == null) {
            throw new NoSuchWorkerException(String.valueOf(workerId));
        } else {
            if (className == null) {
                result = new UnloadableWorker("Missing property " + WorkerConfig.IMPLEMENTATION_CLASS);
            } else {
                try {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Loading worker with class name: " + className);
                    }
                    ClassLoader cl = this.getClass().getClassLoader();
                    Class<?> implClass = cl.loadClass(className);
                    result = (IWorker) implClass.newInstance();
                } catch (ClassNotFoundException e) {
                    result = new UnloadableWorker("Worker class not found (is the module included in the build?): " + className + ": " + e.getLocalizedMessage());
                } catch (IllegalAccessException e) {
                    result = new UnloadableWorker("Could not access worker class: " + className + ": " + e.getLocalizedMessage());
                } catch (InstantiationException e) {
                    result = new UnloadableWorker("Could not instantiate worker class: " + className + ": " + e.getLocalizedMessage());
                }
            }

            initWorker(result, workerId, config);

            if (LOG.isTraceEnabled()) {
                LOG.trace("loadWorker(" + workerId + "): instance " + result);
            }

            cache.putWorkerOnly(workerId, result);
        }
        return result;
    }
    
    private WorkerWithComponents loadWorkerWithComponents(final WorkerIdentifier wi, final SignServerContext context) throws NoSuchWorkerException {
        final int workerId;
        if (wi.hasId()) {
            workerId = wi.getId();
        } else {
            workerId = workerConfigHome.findId(wi.getName());
        }
        
        WorkerWithComponents result;
        if (LOG.isTraceEnabled()) {
            LOG.trace(">loadWorkerWithComponents(" + workerId + ")");
        }
        final IWorker worker = getWorker(wi);

        final WorkerConfig config = worker.getConfig();
        @SuppressWarnings("deprecation")
        final EntityManager em = context.getEntityManager();
        final List<String> createErrors = new LinkedList<>();

        // Worker Logger
        IWorkerLogger workerLogger = null;
        try {
            workerLogger = getWorkerLogger(workerId, config, em);
        } catch (SignServerException ex) {
            createErrors.add(ex.getLocalizedMessage());
        }

        // Authorizer
        IAuthorizer authorizer = null;
        if (worker instanceof IProcessable) {
            try {
                final String authType = ((IProcessable) worker).getAuthenticationType();
                authorizer = getAuthenticator(workerId, authType, config, em);
            } catch (SignServerException ex) {
                createErrors.add(ex.getLocalizedMessage());
            }
        }

        // Accounter
        IAccounter accounter = null;
        try {
            accounter = getAccounter(workerId, config, em);
        } catch (SignServerException ex) {
            createErrors.add(ex.getLocalizedMessage());
        }

        // Archivers
        List<Archiver> archivers = null;
        try {
            archivers = getArchivers(workerId, config, context);
        } catch (SignServerException ex) {
            createErrors.add(ex.getLocalizedMessage());
        }

        // Worker with components
        result = new WorkerWithComponents(workerId, worker, createErrors, workerLogger, authorizer, accounter, archivers);
        cache.putWorkerWithComponents(workerId, result);
        return result;
    }
    
    /*private IWorker loadWorker(final String workerName) throws NoSuchWorkerException {
        return loadWorker(workerConfigHome.findId(workerName));
    }
    
    private WorkerWithComponents loadWorkerWithComponents(final String workerName, final SignServerContext context) throws NoSuchWorkerException {
        return loadWorkerWithComponents(workerConfigHome.findId(workerName), context);
    }*/

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
    /*public synchronized int getWorkerIdFromName(final String workerName) throws NoSuchWorkerException {
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
    }*/

    private void initWorker(final IWorker worker, final int workerId, final WorkerConfig config) {
        final String cryptoTokenName = config.getProperty("CRYPTOTOKEN");
        SignServerContext context = workerContext.newInstance();
        if (cryptoTokenName != null) {
            context.setCryptoTokenSupplier(new CryptoTokenSupplier() {

                @Override
                public ICryptoToken getCurrentCryptoToken() throws SignServerException {
                    synchronized (WorkerFactory.this) {
                        try {
                            IWorker cryptoWorker = getWorker(new WorkerIdentifier(cryptoTokenName));
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
        if (LOG.isTraceEnabled()) {
            LOG.trace(">flush()");
        }
        cache.clearAll();
    }

    /**
     * Method used to force a reload of worker.
     * @param id of worker
     */
    public synchronized void reloadWorker(WorkerIdentifier wi) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">reloadWorker(" + wi + ")");
        }
        if (wi.hasName() || (wi.hasId() && wi.getId() != null)) {
            cache.clear(wi);
            if (LOG.isTraceEnabled()) {
                LOG.trace("reloadWorker(" + wi + "): removed instance");
            }
        }

        try {
            loadWorker(wi);
        } catch (NoSuchWorkerException ex) {
            LOG.error("Error reloading worker : " + ex.getMessage());
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
    private IAuthorizer getAuthenticator(int workerId, String authType, WorkerConfig config, EntityManager em)
            throws SignServerException {
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
        return auth;
    }

    private IWorkerLogger getWorkerLogger(final int workerId,
            final WorkerConfig config, final EntityManager em)
            throws SignServerException {
        IWorkerLogger workerLogger;
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
        workerLogger.init(workerId, config, workerContext.newInstance());
        return workerLogger;
    }

    private IAccounter getAccounter(final int workerId,
            final WorkerConfig config, final EntityManager em)
            throws SignServerException {
        final IAccounter accounter;
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
        return accounter;
    }

    private List<Archiver> getArchivers(final int workerId,
            final WorkerConfig config, final SignServerContext context)
            throws SignServerException {
        final List<Archiver> archivers = new LinkedList<>();
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
            }
        }
        return archivers;
    }

    public synchronized Collection<Integer> getCachedWorkerIds() {
        return cache.keySet();
    }

}
