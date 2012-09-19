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

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Random;
import java.util.logging.Level;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.*;
import org.signserver.common.*;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.test.random.FailedException;
import org.signserver.test.random.Task;
import org.signserver.test.random.WorkerSpec;

/**
 * Signs a sample document.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class Sign implements Task {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(Sign.class);
    
    private final WorkerSpec signer;
    private final IWorkerSession.IRemote workerSession;
    private final Random random;
    private int counter;
    private final RequestContext requestContext = new RequestContext();
    
    private static final String TESTXML1 = "<doc>Some sample XML to sign</doc>";

    public Sign(final WorkerSpec signerId, final IWorkerSession.IRemote workerSession, final Random random) {
        this.signer = signerId;
        this.workerSession = workerSession;
        this.random = random;
    }
    
    @Override
    public void run() throws FailedException {
        LOG.debug(">run");
        try {
            final int reqid = counter++;
            LOG.info("Worker " + signer + " signing: " + counter);
            process(signer, reqid);
        } catch (IllegalRequestException ex) {
            throw new FailedException("Illegal request", ex);
        } catch (CryptoTokenOfflineException ex) {
            throw new FailedException("Worker offline", ex);
        } catch (SignServerException ex) {
            throw new FailedException("Generic error", ex);
        }
        LOG.debug("<run");
    }
    
    private void process(final WorkerSpec signer, final int reqid) throws FailedException, IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        final ProcessResponse result;
        switch (signer.getWorkerType()) {
            case xml: {
                // Process
                final GenericSignRequest signRequest = new GenericSignRequest(reqid, TESTXML1.getBytes());
                final ProcessResponse response = workerSession.process(signer.getWorkerId(), signRequest, requestContext);
                
                // Check result
                GenericSignResponse res = (GenericSignResponse) response;
                final byte[] data = res.getProcessedData();
                // Check that we got a signed XML back
                String xml = new String(data);
                if (!xml.contains("xmldsig")) {
                    throw new FailedException("Response was not signed: \"" + xml + "\"");
                }
                break;
            }
            case tsa: {
                try {
                    // Process
                    final TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
                    final int nonce = random.nextInt();
                    final TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(nonce));
                    byte[] requestBytes = timeStampRequest.getEncoded();

                    GenericSignRequest signRequest =
                            new GenericSignRequest(reqid, requestBytes);
                    final GenericSignResponse res = (GenericSignResponse) workerSession.process(signer.getWorkerId(), signRequest, requestContext);

                    // Check result
                    if (reqid != res.getRequestID()) {
                        throw new FailedException("Expected request id: " + reqid + " but was " + res.getRequestID());
                    }

                    final Certificate signercert = res.getSignerCertificate();
                    if (signercert == null) {
                        throw new FailedException("No certificate returned");
                    }

                    final TimeStampResponse timeStampResponse = new TimeStampResponse((byte[]) res.getProcessedData());
                    timeStampResponse.validate(timeStampRequest);

                    if (timeStampResponse.getStatus() != PKIStatus.GRANTED) {
                        throw new FailedException("Token was not granted: " + timeStampResponse.getStatus());
                    }

                    if (timeStampResponse.getTimeStampToken() == null) {
                        throw new FailedException("No token returned");
                    }
                    break;
                } catch (TSPException ex) {
                    LOG.error("Verification error", ex);
                    throw new FailedException("Response could not be verified: " + ex.getMessage());
                } catch (IOException ex) {
                    LOG.error("Could not create request", ex);
                    throw new FailedException("Could not create request: " + ex.getMessage());
                }
            }
            default:
                throw new IllegalRequestException("Unsupported workerType: " + signer.getWorkerType());
        }
    }
    
    private void checkResponse(final WorkerSpec signer, final ProcessResponse response) throws FailedException {
        switch (signer.getWorkerType()) {
            case xml: {
                GenericSignResponse res = (GenericSignResponse) response;
                final byte[] data = res.getProcessedData();
                // Check that we got a signed XML back
                String xml = new String(data);
                if (!xml.contains("xmldsig")) {
                    throw new FailedException("Response was not signed: \"" + xml + "\"");
                }
                break;
            }
            case tsa: {
                
            }
            default:
                throw new FailedException("Unsupported workerType: " + signer.getWorkerType());
        }
    }
    
}
