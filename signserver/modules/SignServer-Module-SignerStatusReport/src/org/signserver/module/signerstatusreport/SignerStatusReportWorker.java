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
package org.signserver.module.signerstatusreport;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.ejb.EJB;
import javax.naming.NamingException;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericServletResponse;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerException;
import org.signserver.common.SignerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.SignServerContext;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.cryptotokens.NullCryptoToken;
import org.signserver.server.signers.BaseSigner;

/**
 * Worker for getting a signer's status report. When called without any request 
 * properties, it produces the same output as the SignerStatusReportTimedService 
 * but returned in the response instead of written to a file.
 *
 * Worker properties:
 *  WORKERS: Comma separated list of workerName of signers to include in the 
 * report
 * 
 * The worker accepts a GenericSignRequest.
 * 
 * Request properties:
 *  (none)
 * 
 * @author Markus Kilås
 * @version $Id$
 * @see SignerStatusReportTimedService
 */
public class SignerStatusReportWorker extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SignerStatusReportWorker.class);
    
    /** Property WORKERS. **/
    private static final String PROPERTY_WORKERS = SignerStatusReportTimedService.PROPERTY_WORKERS;
    
    private static final ICryptoToken CRYPTO_TOKEN = new NullCryptoToken(SignerStatus.STATUS_ACTIVE);
    
    private SignerStatusReportBuilder reportBuilder;

    /** Workersession. */
    @EJB
    private IWorkerSession workerSession; // FIXME: Better to somehow inject this
    
    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        List<String> workers = new LinkedList<String>();
        final String workersValue = config.getProperty(PROPERTY_WORKERS);
        if (workersValue == null) {
            LOG.error("Property WORKERS missing!");
        } else {
            workers.addAll(Arrays.asList(workersValue.split(",")));
        }
        reportBuilder = new SignerStatusReportBuilder(workers, getWorkerSession(), ((SignServerContext) workerContext).getKeyUsageCounterDataService());
        LOG.info("Worker[" + workerId +"]: " + "Workers: " + workers.size());
    }
    
    @Override
    public ProcessResponse processData(ProcessRequest request, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        final GenericSignRequest signRequest;
        if (request instanceof GenericSignRequest) {
            signRequest = (GenericSignRequest) request;
        } else {
            throw new IllegalRequestException("Recieved request was not of expected type.");
        }
        
        // Process the request
        String responseData = reportBuilder.buildReport().toString();

        return new GenericServletResponse(signRequest.getRequestID(), responseData.getBytes(), null, null, null, "text/plain");
    }

    private IWorkerSession getWorkerSession() {
        if (workerSession == null) {
            try {
                workerSession = ServiceLocator.getInstance().lookupRemote(
                        IWorkerSession.IRemote.class);
            } catch (NamingException ex) {
                throw new RuntimeException("Unable to lookup worker session",
                        ex);
            }
        }
        return workerSession;
    }
    
    @Override
    protected List<String> getSignerCertificateFatalErrors() {
        // This worker does not require any signer certificate so don't
        // report any error about it.
        return Collections.emptyList();
    }
    
    @Override
    protected ICryptoToken getCryptoToken() throws SignServerException {
        ICryptoToken result = super.getCryptoToken();

        // Not configuring a crypto token for this worker is not a problem as
        // this worker does not use a crypto token. Instead a dummy instance
        // is returned.
        if (result == null) {
            result = CRYPTO_TOKEN;
        }

        return result;
    }
}
