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
package org.signserver.server.signers;

import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerStatus;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.server.IServices;

/**
 * Dummy Signer used for test and demonstration purposes.
 *
 * @author Philip Vendil 17 dec 2007
 * @version $Id$
 */
public class DummySigner extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DummySigner.class);
    
    /**
     * Time to wait before sending back the response.
     */
    public static final String WAITTIME = "WAITTIME";

    /**
     * Default wait time i milliseconds.
     */
    public static final String DEFAULT_WAITTIME = "1000";
    
    private boolean active = true;
    
    private Long waitTime;

    /**
     * Method that does nothing, more than returning the data sent after
     * the configured milliseconds. Also simulates CryptTokenOfflineException
     * if the token is off-line.
     * 
     *  Expects GenericSignRequests
     * 
     * @param signRequest Signing request
     * @param requestContext Request context
     * @return Process response
     * @throws IllegalRequestException 
     * @throws CryptoTokenOfflineException If set to offline
     * @throws SignServerException 
     * @see org.signserver.server.IProcessable#processData(org.signserver.common.ProcessRequest, org.signserver.common.RequestContext)
     */
    @Override
    public Response processData(Request signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {

        if (!active) {
            throw new CryptoTokenOfflineException("Error crypto token is offline.");
        }

        try {
            Thread.sleep(getWaitTime());
        } catch (InterruptedException e) {
            LOG.info(e.getMessage());
        }

        SignatureRequest req = (SignatureRequest) signRequest;

        return new SignatureResponse(req.getRequestID(), req.getResponseData(), null, null, null, "text/plain");
    }

    private long getWaitTime() {
        if (waitTime == null) {
            String waitTimeString = config.getProperties().getProperty(WAITTIME, DEFAULT_WAITTIME);
            try {
                waitTime = Long.parseLong(waitTimeString);
            } catch (NumberFormatException e) {
                LOG.error("Property " + WAITTIME + " missconfigured, should only contain integers");
            }
        }
        return waitTime;
    }

    /**
     * Dummy implementation that doesn't check the auth code.
     * 
     * @param authenticationCode PIN
     * @param services Services
     * @throws CryptoTokenAuthenticationFailureException
     * @throws CryptoTokenOfflineException
     * @see org.signserver.server.BaseProcessable#activateSigner(java.lang.String)
     */
    @Override
    public void activateSigner(String authenticationCode, IServices services)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException {
        this.active = true;
    }

    /* (non-Javadoc)
     * @see org.signserver.server.BaseProcessable#deactivateSigner()
     */
    @Override
    public boolean deactivateSigner(IServices services) throws CryptoTokenOfflineException {
        this.active = false;
        return true;
    }

    @Override
    public int getCryptoTokenStatus(IServices services) {
        return active ? WorkerStatus.STATUS_ACTIVE : WorkerStatus.STATUS_OFFLINE;
    }    
}
