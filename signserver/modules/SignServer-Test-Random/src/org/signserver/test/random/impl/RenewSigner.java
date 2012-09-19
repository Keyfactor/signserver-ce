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
package org.signserver.test.random.impl;

import java.util.Properties;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.test.random.FailedException;
import org.signserver.test.random.Task;

/**
 * Renews a signer.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class RenewSigner implements Task {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(RenewSigner.class);
    
    private final int workerId;
    private final int renewee;
    private final IWorkerSession.IRemote workerSession;
    private int counter;
    
    private static final String TESTXML1 = "<doc>Some sample XML to sign</doc>";

    public RenewSigner(int workerId, int renewee, IWorkerSession.IRemote workerSession) {
        this.workerId = workerId;
        this.renewee = renewee;
        this.workerSession = workerSession;
    }
    
    @Override
    public void run() throws FailedException {
        LOG.debug(">run");
        try {
            counter++;
            LOG.info("Worker " + workerId + " Start renewal: " + counter);
            
            final Properties requestProperties = new Properties();
            requestProperties.setProperty("WORKER", String.valueOf(renewee));
            requestProperties.setProperty("AUTHCODE", "foo123"); // TODO
            final GenericPropertiesRequest signRequest = new GenericPropertiesRequest(requestProperties);
            final GenericPropertiesResponse res =  (GenericPropertiesResponse) workerSession.process(workerId, signRequest, new RequestContext());
            final String result = res.getProperties().getProperty("RESULT");
            
            // Check that we got OK back
            if (!"OK".equals(result)) {
                throw new FailedException("Response was not OK: \"" + result + "\", Message: \"" + res.getProperties().getProperty("MESSAGE", ""));
            }           
            LOG.info("Worker " + workerId + " Finished renewal: " + counter);
        } catch (IllegalRequestException ex) {
            throw new FailedException("Illegal request", ex);
        } catch (CryptoTokenOfflineException ex) {
            throw new FailedException("Worker offline", ex);
        } catch (SignServerException ex) {
            throw new FailedException("Generic error", ex);
        }
        LOG.debug("<run");
    }

    public int getReneweeId() {
        return renewee;
    }
    
}
