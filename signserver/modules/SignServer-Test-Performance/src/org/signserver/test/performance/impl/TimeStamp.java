package org.signserver.test.performance.impl;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.ejb.interfaces.IWorkerSession.IRemote;
import org.signserver.test.performance.Task;
import org.signserver.test.performance.FailedException;

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
    public void run() throws FailedException {
        try {
            tsaRequest();
        } catch (TSPException ex) {
            LOG.error("Verification error", ex);
            throw new FailedException("Response could not be verified: " + ex.getMessage());
        } catch (IOException ex) {
            LOG.error("Could not create request", ex);
            throw new FailedException("Could not create request: " + ex.getMessage());
        }

    }

    private void tsaRequest() throws TSPException, IOException {
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

    	LOG.info("Got reply after "
    			+ TimeUnit.NANOSECONDS.toMillis(estimatedTime) + " ms");

    	final byte[] replyBytes = baos.toByteArray();


    	final TimeStampResponse timeStampResponse = new TimeStampResponse(
    			replyBytes);
    	timeStampResponse.validate(timeStampRequest);

    	LOG.info("TimeStampRequest validated");
    }
}
