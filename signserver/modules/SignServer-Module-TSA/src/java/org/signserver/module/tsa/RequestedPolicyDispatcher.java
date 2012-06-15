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
package org.signserver.module.tsa;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import javax.naming.NamingException;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.signserver.common.*;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.ejb.interfaces.IWorkerSession.IRemote;
import org.signserver.server.ITimeStampSignerLookup;
import org.signserver.server.WorkerContext;
import org.signserver.server.dispatchers.BaseDispatcher;
import org.signserver.server.log.IWorkerLogger;
//import org.signserver.server.tsa.org.bouncycastle.tsp.TimeStampResponseGenerator;

/**
 * Dispatching requests to a Time Stamp Unit based on the requested profile.
 *
 * Properties:<br/>
 * DEFAULTWORKER - Worker name or ID to dispatch to in case no policy was requested.
 * USEDEFAULTIFMISMATCH - If true dispatches to DEFAULTWORKER in case no mapping existed for the requested policy OID (default: false)
 * MAPPINGS - Mapping from requested policy OID to a worker name.
 * The property is of the form:
 * POLICYOID1:WORKERNAMEORID1; POLICYOID2:WORKERNAMEORID2; POLICYOID3:WORKERNAMEORID2;
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class RequestedPolicyDispatcher extends BaseDispatcher {

    /** Log4j instance for this class. */
    private static final Logger LOG = Logger.getLogger(
            RequestedPolicyDispatcher.class);

    /** Workersession. */
    private IWorkerSession.IRemote workerSession;
    
    private static final String MAPPINGS = "MAPPINGS";
    private static final String DEFAULTWORKER = "DEFAULTWORKER";
    private static final String USEDEFAULTIFMISMATCH = "USEDEFAULTIFMISMATCH";


    private final Random random = new Random();
    
        private static final String REQUEST_CONTENT_TYPE
            = "application/timestamp-query";
    private static final String RESPONSE_CONTENT_TYPE
            = "application/timestamp-reply";
    
    private Map<String, String> workerMapping = new HashMap<String, String>();
    
    private String defaultWorker;
    private boolean useDefaultIfMismatch;
    
    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        try {
            super.init(workerId, config, workerContext, workerEM);

            String policyWorkerMapping = config.getProperty(MAPPINGS);
            if (policyWorkerMapping == null) {
                LOG.error("Property " + MAPPINGS + " missing!");
            } else {
                workerMapping = parseMapping(policyWorkerMapping);
            }
            
            defaultWorker = config.getProperty(DEFAULTWORKER);
            
            useDefaultIfMismatch = Boolean.parseBoolean(config.getProperty(USEDEFAULTIFMISMATCH, "false"));
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(new StringBuilder()
                        .append("workerMapping: ").append(workerMapping).append("\n")
                        .append("defaultWorker: ").append(defaultWorker).append("\n")
                        .append("useDefaultIfMismatch: ").append(useDefaultIfMismatch).toString());
            }
            
            workerSession = ServiceLocator.getInstance().lookupRemote(
                        IWorkerSession.IRemote.class);
        } catch (NamingException ex) {
            LOG.error("Unable to lookup worker session", ex);
        }
    }

    @Override
    public ProcessResponse processData(final ProcessRequest signRequest,
            final RequestContext context) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        final GenericSignResponse result;
        
        // Log values
        final Map<String, String> logMap = (Map<String, String>) context.get(RequestContext.LOGMAP);
        
        // Check context
        final RequestContext nextContext = context;
        if (context.get(this.getClass().getName()) != null) {
            throw new SignServerException("Dispatcher called more then one time for the same request. Aborting.");
        } else {
            context.put(this.getClass().getName(), "called");
        }

        // Check that the request contains a valid TimeStampRequest object.
        if (!(signRequest instanceof GenericSignRequest)) {
            throw new IllegalRequestException("Recieved request wasn't a expected GenericSignRequest.");
        }
        final ISignRequest sReq = (ISignRequest) signRequest;
        
        // Get TimeStampRequest
        final TimeStampRequest timeStampRequest;
        if (sReq.getRequestData() instanceof TimeStampRequest) {
            timeStampRequest = (TimeStampRequest) sReq.getRequestData();
        } else if (sReq.getRequestData() instanceof byte[]) {
            try {
                timeStampRequest =  new TimeStampRequest((byte[]) sReq.getRequestData());
            } catch (IOException ex) {
                throw new IllegalRequestException("Could not parse TimeStampRequest", ex);
            }
        } else {
            throw new IllegalRequestException("Expected a TimeStampRequest");
        }
        
        try {
            // Add to context
            if (timeStampRequest.getReqPolicy() != null) {
                nextContext.put(ITimeStampSignerLookup.TSA_REQUESTEDPOLICYOID, timeStampRequest.getReqPolicy().getId());
            }
            
            // Find to which worker the request should be dispatched
            final String toWorker = lookupWorkerToDispatchTo(timeStampRequest, context);
            if (toWorker == null) {
                final TimeStampResponseGenerator gen = new TimeStampResponseGenerator(null, null);
                final TimeStampResponse resp = gen.generateFailResponse(PKIStatus.REJECTION, PKIFailureInfo.unacceptedPolicy, "request contains unknown policy.");

                // Auditlog
                logMap.put(IWorkerLogger.LOG_CLIENT_AUTHORIZED, "false");
                logMap.put(IWorkerLogger.LOG_EXCEPTION, "requested policy not supported");

                result = new GenericServletResponse(sReq.getRequestID(), resp.getEncoded(), null, null, null, RESPONSE_CONTENT_TYPE);
            } else {
                int toWorkerId = 0;
                try {
                    toWorkerId = Integer.parseInt(toWorker);
                } catch (NumberFormatException ignored) {}
                if (toWorkerId < 1) {
                    toWorkerId = getWorkerSession().getWorkerId(toWorker);
                }
                
                // Mark request comming from a dispatcher so the DispatchedAuthorizer can be used
                context.put(RequestContext.DISPATCHER_AUTHORIZED_CLIENT, true);
                
                HttpServletRequest httpRequest = null;
                if (sReq instanceof GenericServletRequest) {
                    httpRequest = ((GenericServletRequest) sReq).getHttpServletRequest();   
                }
                ProcessRequest newRequest = new GenericServletRequest(sReq.getRequestID(), (byte[]) sReq.getRequestData(), httpRequest);
                
                result = (GenericSignResponse) getWorkerSession().process(toWorkerId, newRequest, context);
            }
        } catch (IOException e) {
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION, e.getMessage());
            throw new SignServerException("Response message could not be constructed", e);
        } catch (TSPException e) {
            throw new SignServerException("Response message could not be constructed", e);
        }
        return result;
    }

    public IRemote getWorkerSession() {
        return workerSession;
    }
    
    private Map<String, String> parseMapping(String mapping) {
        
        if (mapping == null) {
            return Collections.emptyMap();
        }
        final String[] entries = mapping.split(";");
        final Map<String, String> result = new HashMap<String, String>();
        for (String entry : entries) {
            final String[] keyvalue = entry.trim().split(":");
            if (keyvalue.length == 2) {
                result.put(keyvalue[0].trim(), keyvalue[1].trim());
            }
        }
        if (LOG.isDebugEnabled()) {
            final StringBuilder str = new StringBuilder();
            str.append("Authorization mapping: ");
            str.append("\n");
            for (Map.Entry<String, String> entry : result.entrySet()) {
                str.append("\"");
                str.append(entry.getKey());
                str.append("\"");
                str.append(" --> ");
                str.append("\"");
                str.append(entry.getValue());
                str.append("\"");
                str.append("\n");
            }
            LOG.debug(str.toString());
        }
        return result;
    }

    protected String lookupWorkerToDispatchTo(TimeStampRequest timeStampRequest, RequestContext requestContext) {
        String result;
        if (timeStampRequest.getReqPolicy() == null) {
            result = defaultWorker;
        } else {
            result = workerMapping.get(timeStampRequest.getReqPolicy().getId());
            if (result == null && useDefaultIfMismatch) {
                result = defaultWorker;
            }
        }
        return result;
    }

    
}
