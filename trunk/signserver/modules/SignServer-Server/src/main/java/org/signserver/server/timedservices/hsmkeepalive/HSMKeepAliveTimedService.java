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
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.ServiceContext;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.server.ServiceExecutionFailedException;
import org.signserver.server.WorkerContext;
import org.signserver.server.timedservices.BaseTimedService;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.server.IServices;

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

    private List<WorkerIdentifier> cryptoTokens;


    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        final String cryptoTokensValue = config.getPropertyThatCouldBeEmpty(CRYPTOTOKENS);

        if (cryptoTokensValue != null) {
            cryptoTokens = new LinkedList<>();
            for (String token : Arrays.asList(cryptoTokensValue.split(","))) {
                cryptoTokens.add(WorkerIdentifier.createFromIdOrName(token.trim()));
            }
        }
    }
    
    @Override
    public void work(final ServiceContext context) throws ServiceExecutionFailedException {
        final WorkerSessionLocal session = context.getServices().get(WorkerSessionLocal.class);
        if (cryptoTokens != null) {
            for (final WorkerIdentifier wi : cryptoTokens) {
                try {
                    session.testKey(wi, null, null);
                } catch (CryptoTokenOfflineException e) {
                    LOG.warn("Crypto token offline for worker " + wi +
                            ": " + e.getMessage());
                } catch (InvalidWorkerIdException e) {
                    LOG.error("Invalid worker ID: " + e.getMessage());
                } catch (KeyStoreException e) {
                    LOG.error("Keystore exception for worker " + wi +
                            ": " + e.getMessage());
                }
            }
        }
    }

    @Override
    protected List<String> getFatalErrors(IServices services) {
        final List<String> errors = new LinkedList<>(super.getFatalErrors(services));
        
        if (cryptoTokens == null) {
            errors.add("Must specify " + CRYPTOTOKENS);
        }
        
        errors.addAll(getCryptoworkerErrors(services));
        return errors;
    }
    
    private List<String> getCryptoworkerErrors(final IServices services) {
        final List<String> errors = new LinkedList<>();
        final WorkerSessionLocal session = services.get(WorkerSessionLocal.class);
        
        if (session != null && cryptoTokens != null) {
            for (final WorkerIdentifier wi : cryptoTokens) {
                try {
                    session.getStatus(wi);
                } catch (InvalidWorkerIdException e) {
                    errors.add("Invalid worker: " + wi);
                }
            }
        }   
        return errors;
    }
}
