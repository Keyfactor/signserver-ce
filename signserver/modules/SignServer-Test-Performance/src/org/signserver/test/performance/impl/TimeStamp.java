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
package org.signserver.test.performance.impl;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.signserver.test.performance.FailedException;
import org.signserver.test.performance.Task;

/**
 * Requests a timestamp.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class TimeStamp implements Task {

    /** Logger for this class */
    Logger LOG = Logger.getLogger(TimeStamp.class);
    
    private String tsaUrl;
    private Random random;

    public TimeStamp(final String url, final Random random) {
        this.tsaUrl = url;
        this.random = random;
    }
    
    @Override
    public long run() throws FailedException {
        try {
            return tsaRequest();
        } catch (TSPException ex) {
            LOG.error("Verification error", ex);
            throw new FailedException("Response could not be verified: " + ex.getMessage());
        } catch (IOException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Could not create request", ex);
            }
            throw new FailedException("Could not create request: " + ex.getMessage());
        }
    }

    private long tsaRequest() throws TSPException, IOException, FailedException {
    	final TimeStampRequestGenerator timeStampRequestGenerator =
    			new TimeStampRequestGenerator();
    	final int nonce = random.nextInt();

    	byte[] digest = new byte[20];
    	final TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
    			TSPAlgorithms.SHA1, digest, BigInteger.valueOf(nonce));
    	final byte[] requestBytes = timeStampRequest.getEncoded();

    	URL url;
    	URLConnection urlConn;
    	DataOutputStream printout;
    	DataInputStream input;

    	url = new URL(tsaUrl);

    	// Take start time
    	final long startMillis = System.currentTimeMillis();
    	final long startTime = System.nanoTime();
    	if (LOG.isDebugEnabled()) {
    		LOG.debug("Sending request at: " + startMillis);
    	}

    	urlConn = url.openConnection();

    	urlConn.setDoInput(true);
    	urlConn.setDoOutput(true);
    	urlConn.setUseCaches(false);
    	urlConn.setRequestProperty("Content-Type",
    			"application/timestamp-query");

    	// Send POST output.
    	printout = new DataOutputStream(urlConn.getOutputStream());
    	printout.write(requestBytes);
    	printout.flush();
    	printout.close();

    	// Get response data.
    	input = new DataInputStream(urlConn.getInputStream());

    	byte[] ba = null;
    	final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	do {
    		if (ba != null) {
    			baos.write(ba);
    		}
    		ba = new byte[input.available()];

    	} while (input.read(ba) != -1);

    	// Take stop time
    	final long estimatedTime = System.nanoTime() - startTime;
    	final long timeInMillis = TimeUnit.NANOSECONDS.toMillis(estimatedTime);
    	
        if (LOG.isDebugEnabled()) {
            LOG.debug("Got reply after " + timeInMillis + " ms");
        }

    	final byte[] replyBytes = baos.toByteArray();


    	final TimeStampResponse timeStampResponse = new TimeStampResponse(
    			replyBytes);
    	timeStampResponse.validate(timeStampRequest);
    	LOG.debug("TimeStampResponse validated");
        
        // TODO: Maybe in the future we would like to make the below failure 
        // check configurable or count the failure but without failing the test
        if (timeStampResponse.getStatus() != PKIStatus.GRANTED
                && timeStampResponse.getStatus() != PKIStatus.GRANTED_WITH_MODS) {
            throw new FailedException("Token was not granted. Status was: " + timeStampResponse.getStatus()
                    + " (" + timeStampResponse.getStatusString() + ")");
        } else {
            LOG.debug("TimeStampResponse granted");
        }
    	
    	return timeInMillis;
    }
}
