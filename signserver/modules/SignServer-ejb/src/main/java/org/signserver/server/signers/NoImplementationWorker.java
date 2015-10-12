/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.signers;

import java.util.LinkedList;
import java.util.List;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.StaticWorkerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.server.IServices;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class NoImplementationWorker extends BaseSigner {
    private static final String WORKER_TYPE = "Worker";

    
    @Override
    protected boolean isNoCertificates() {
        return true;
    }

    @Override
    public WorkerStatus getStatus(List<String> additionalFatalErrors, final IServices services) {
        WorkerStatus status = super.getStatus(additionalFatalErrors, services);
        if (status instanceof StaticWorkerStatus) {
            // Adjust worker type
            ((StaticWorkerStatus) status).getInfo().setWorkerType(WORKER_TYPE);
        }
        return status;
    }
    
    @Override
    public List<String> getFatalErrors() {
        LinkedList<String> errors = new LinkedList<>();
        errors.add("Missing property " + WorkerConfig.IMPLEMENTATION_CLASS);
        return errors;
    }

    @Override
    public ProcessResponse processData(ProcessRequest signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        throw new SignServerException("Worker is misconfigured");
    }
}
