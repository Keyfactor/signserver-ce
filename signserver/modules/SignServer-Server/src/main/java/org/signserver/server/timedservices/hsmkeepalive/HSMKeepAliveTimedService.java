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
package org.signserver.server.timedservices.hsmkeepalive;

import java.security.KeyStoreException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.ejb.EJB;
import javax.naming.NamingException;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.ServiceLocator;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.ServiceExecutionFailedException;
import org.signserver.server.WorkerContext;
import org.signserver.server.timedservices.BaseTimedService;

/**
 * Timed service calling testKey() on selected (crypto)workers.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class HSMKeepAliveTimedService extends BaseTimedService {

    private static final Logger LOG = Logger.getLogger(HSMKeepAliveTimedService.class);
    
    public static String CRYPTOTOKENS = "CRYPTOTOKENS";
    
    static String TESTKEY = "TESTKEY";
    static String DEFAULTKEY = "DEFAULTKEY";

    private List<String> cryptoTokens;
 
    @EJB
    private IWorkerSession workerSession;
    
    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        final String cryptoTokensValue = config.getProperty(CRYPTOTOKENS);

        if (cryptoTokensValue != null) {
            cryptoTokens = new LinkedList<String>();
            cryptoTokens.addAll(Arrays.asList(cryptoTokensValue.split(",")));
        }
    }
    
    IWorkerSession getWorkerSession() {
        if (workerSession == null) {
            try {
                workerSession = ServiceLocator.getInstance().lookupLocal(
                        IWorkerSession.class);
            } catch (NamingException ex) {
                throw new RuntimeException("Unable to lookup worker session",
                        ex);
            }
        }
        return workerSession;
    }

    
    
    @Override
    public void work() throws ServiceExecutionFailedException {
        final IWorkerSession session = getWorkerSession();

        if (cryptoTokens != null) {
            for (final String workerIdOrName : cryptoTokens) {
                int cryptoWorkerId;

                try {
                    cryptoWorkerId = Integer.valueOf(workerIdOrName);
                } catch (NumberFormatException e) {
                    cryptoWorkerId = session.getWorkerId(workerIdOrName);
                }

                if (cryptoWorkerId == 0) {
                    LOG.error("No such worker: " + workerIdOrName);
                }

                final String keyAlias = getKeyAliasForWorker(session, cryptoWorkerId);

                if (keyAlias == null) {
                    LOG.error("TESTKEY or DEFAULTKEY is not set for worker: " +
                            workerIdOrName);
                    continue;
                }

                try {
                    session.testKey(cryptoWorkerId, keyAlias, null);
                } catch (CryptoTokenOfflineException e) {
                    LOG.warn("Crypto token offline for worker " + workerIdOrName +
                            ": " + e.getMessage());
                } catch (InvalidWorkerIdException e) {
                    LOG.error("Invalid worker ID: " + e.getMessage());
                } catch (KeyStoreException e) {
                    LOG.error("Keystore exception for worker " + workerIdOrName +
                            ": " + e.getMessage());
                }
            }
        }
    }
    
    /**
     * Get key alias to use for testing a given worker's crypto token.
     * Use TESTKEY if available, otherwise DEFAULTKEY.
     * 
     * @param workerId Worker ID to get key for
     * @return Key alias, or null if no key alias was found
     */
    private String getKeyAliasForWorker(final IWorkerSession session, final int workerId) {
        final WorkerConfig workerConfig =
                session.getCurrentWorkerConfig(workerId);
        
        final String testKey = workerConfig.getProperty(TESTKEY);
        final String defaultKey = workerConfig.getProperty(DEFAULTKEY);
        
        return testKey != null ? testKey : defaultKey;
    }

    @Override
    protected List<String> getFatalErrors() {
        final List<String> errors = new LinkedList<String>(super.getFatalErrors());
        
        if (cryptoTokens == null) {
            errors.add("Must specify " + CRYPTOTOKENS);
        }
        
        errors.addAll(getCryptoworkerErrors());
        return errors;
    }
    
    private List<String> getCryptoworkerErrors() {
        final List<String> errors = new LinkedList<String>();
        final IWorkerSession session = getWorkerSession();
        
        if (session != null && cryptoTokens != null) {
            int cryptoWorkerId;
            for (final String workerIdOrName : cryptoTokens) {
                try {
                    cryptoWorkerId = Integer.valueOf(workerIdOrName);
                    
                    try {
                        session.getStatus(cryptoWorkerId);
                    } catch (InvalidWorkerIdException e) {
                        errors.add("Invalid worker ID: " + cryptoWorkerId);
                    }
                } catch (NumberFormatException e) {
                    cryptoWorkerId = session.getWorkerId(workerIdOrName);
                    
                    if (cryptoWorkerId == 0) {
                        errors.add("No such worker: " + workerIdOrName);
                    }
                }
            }
        }
        
        return errors;
    }
}
