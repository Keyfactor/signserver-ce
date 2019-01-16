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

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.NullCryptoToken;
import org.signserver.server.signers.BaseSigner;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.server.IServices;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.entities.IKeyUsageCounterDataService;

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
    
    private static final ICryptoTokenV4 CRYPTO_TOKEN = new NullCryptoToken(WorkerStatus.STATUS_ACTIVE);
    
    private List<String> workers;

    
    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        workers = new LinkedList<>();
        final String workersValue = config.getProperty(PROPERTY_WORKERS);
        if (workersValue == null) {
            LOG.error("Property WORKERS missing!");
        } else {
            workers.addAll(Arrays.asList(workersValue.split(",")));
        }
        LOG.info("Worker[" + workerId +"]: " + "Workers: " + workers.size());
    }
    
    @Override
    public Response processData(Request request, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        final SignatureRequest signRequest;
        if (request instanceof SignatureRequest) {
            signRequest = (SignatureRequest) request;
        } else {
            throw new IllegalRequestException("Received request was not of expected type.");
        }
        
        // Process the request
        WritableData responseData = ((SignatureRequest) request).getResponseData();
        SignerStatusReportBuilder reportBuilder = new SignerStatusReportBuilder(workers, requestContext.getServices().get(WorkerSessionLocal.class), requestContext.getServices().get(IKeyUsageCounterDataService.class));
        
        try (PrintWriter out = new PrintWriter(responseData.getAsOutputStream())) {
            out.append(reportBuilder.buildReport());
        } catch (IOException ex) {
            throw new SignServerException("IO error", ex);
        }
        
        // The client can be charged for the request
        requestContext.setRequestFulfilledByWorker(true);

        return new SignatureResponse(signRequest.getRequestID(), responseData, null, null, null, "text/plain");
    }

    @Override
    protected boolean isNoCertificates() {
        // This worker does not require any signer certificate so don't
        // report any error or information about it.
        return true;
    }

    @Override
    public ICryptoTokenV4 getCryptoToken(IServices services) throws SignServerException {
        ICryptoTokenV4 result = super.getCryptoToken(services);

        // Not configuring a crypto token for this worker is not a problem as
        // this worker does not use a crypto token. Instead a dummy instance
        // is returned.
        if (result == null) {
            result = CRYPTO_TOKEN;
        }

        return result;
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        final List<String> fatalErrors = super.getFatalErrors(services);
        
        if (workers.isEmpty()) {
            fatalErrors.add("Property WORKERS missing");
        }
        
        return fatalErrors;
    }
}
