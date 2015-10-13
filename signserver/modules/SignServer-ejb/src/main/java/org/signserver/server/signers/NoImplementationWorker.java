/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.signers;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.apache.log4j.Logger;
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
import org.signserver.server.ServiceExecutionFailedException;
import org.signserver.server.timedservices.ITimedService;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class NoImplementationWorker extends BaseSigner implements ITimedService {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(NoImplementationWorker.class);

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

    @Override
    public void work() throws ServiceExecutionFailedException {
        LOG.error("Service is misconfigured");
    }

    @Override
    public long getNextInterval() {
        return DONT_EXECUTE;
    }

    @Override
    public boolean isActive() {
        return false;
    }

    @Override
    public boolean isSingleton() {
        return false;
    }

    @Override
    public Set<LogType> getLogTypes() {
        return Collections.emptySet();
    }
}
