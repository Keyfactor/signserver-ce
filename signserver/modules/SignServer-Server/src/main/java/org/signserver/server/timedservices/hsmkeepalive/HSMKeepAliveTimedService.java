/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
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
 * Timed service 
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class HSMKeepAliveTimedService extends BaseTimedService {

    private static Logger LOG = Logger.getLogger(HSMKeepAliveTimedService.class);
    
    public static String CRYPTOWORKERS = "CRYPTOWORKERS";
    
    private static String TESTKEY = "TESTKEY";
    private static String DEFAULTKEY = "DEFAULTKEY";

    private List<String> cryptoWorkers = new LinkedList<String>();
    private List<String> fatalErrors = new LinkedList<String>();
    
    @EJB
    private IWorkerSession workerSession;
    
    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        try {
            super.init(workerId, config, workerContext, workerEM);

            final String cryptoWorkersValue = config.getProperty(CRYPTOWORKERS);

            if (cryptoWorkersValue == null) {
                fatalErrors.add("Must specify " + CRYPTOWORKERS);
            }

            cryptoWorkers.addAll(Arrays.asList(cryptoWorkersValue.split(",")));

            workerSession = ServiceLocator.getInstance().lookupLocal(
                            IWorkerSession.class);
        } catch (NamingException e) {
            LOG.error("Unable to lookup worker session", e);
        }
    }

    
    
    @Override
    public void work() throws ServiceExecutionFailedException {
        for (final String workerIdOrName : cryptoWorkers) {
            int workerId;
            
            try {
                workerId = Integer.valueOf(workerIdOrName);
            } catch (NumberFormatException e) {
                workerId = workerSession.getWorkerId(workerIdOrName);
            }
            
            if (workerId == 0) {
                LOG.error("No such worker: " + workerIdOrName);
            }
            
            final String keyAlias = getKeyAliasForWorker(workerId);
            
            if (keyAlias == null) {
                LOG.error("TESTKEY or DEFAULTKEY is not set for worker: " +
                        workerIdOrName);
                return;
            }
            
            try {
                workerSession.testKey(workerId, keyAlias, null);
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
    
    /**
     * Get key alias to use for testing a given worker's crypto token.
     * Use TESTKEY if available, otherwise DEFAULTKEY.
     * 
     * @param workerId Worker ID to get key for
     * @return Key alias, or null if no key alias was found
     */
    private String getKeyAliasForWorker(final int workerId) {
        final WorkerConfig workerConfig =
                workerSession.getCurrentWorkerConfig(workerId);
        
        final String testKey = workerConfig.getProperty(TESTKEY);
        final String defaultKey = workerConfig.getProperty(DEFAULTKEY);
        
        return testKey != null ? testKey : defaultKey;
    }
    
}
