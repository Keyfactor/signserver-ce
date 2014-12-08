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
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.apache.log4j.Logger;
import java.io.InputStream;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.test.performance.FailedException;
import org.signserver.test.performance.Task;

/**
 * 
 * Invoke a document signer
 * 
 * @author Marcus Lundblad
 * @version $Id: PDFSign.java 3424 2013-04-08 11:33:56Z malu9369 $
 *
 */
public class DocumentSigner implements Task {
    private static Logger LOG = Logger.getLogger(DocumentSigner.class);
    
    private static final String CRLF = "\r\n";
    private static final String BOUNDARY = "------------------signserver";
    
    private String url;
    private boolean useWorkerServlet;
    
    private String workerNameOrId;
    private final Random random;
    private byte[] data;

    private final String userPrefix;
    private final Integer userSuffixMin;
    private final Integer userSuffixMax;

    public DocumentSigner(final String url, final boolean useWorkerServlet, 
            final byte[] data, final String workerNameOrId, final Random random,
            final String userPrefix, final Integer userSuffixMin, final Integer userSuffixMax) {
        this.url = url;
        this.useWorkerServlet = useWorkerServlet;
        this.data = data;
        this.workerNameOrId = workerNameOrId;
        this.random = random;
        this.userPrefix = userPrefix;
        this.userSuffixMin = userSuffixMin;
        this.userSuffixMax = userSuffixMax;
    }
    
    @Override
    public long run() throws FailedException {
        try {
            return documentRequest();
        } catch (IOException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Could not create request", ex);
            }
            throw new FailedException("Could not create request: " + ex.getMessage());
        }
    }
    
    /**
     * Issue a request to a documt signer as configured for the Task.
     * 
     * @return Run time (in ms).
     * @throws IOException
     */
    private long documentRequest() throws IOException {
        URL url;
        URLConnection urlConn;

        final String requestUrl;
        
        if (useWorkerServlet) {
            requestUrl = this.url + "/" + workerNameOrId;
        } else {
            requestUrl = this.url;
        }

        url = new URL(requestUrl);

        // Take start time
        final long startMillis = System.currentTimeMillis();
        final long startTime = System.nanoTime();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending request at: " + startMillis);
        }

        urlConn = url.openConnection();

        urlConn.setDoOutput(true);
        urlConn.setAllowUserInteraction(false);

        // Send with username
        if (userPrefix != null) {
            final String username;
            final String password = "";
            if (userSuffixMin == null) {
                username = userPrefix;
            } else {
                username = userPrefix + (userSuffixMin + random.nextInt(userSuffixMax - userSuffixMin + 1));
            }
            urlConn.setRequestProperty("Authorization", "Basic " + new String(Base64.encode((username + ":" + password).getBytes())));
            if (LOG.isDebugEnabled()) {
                LOG.debug("Username: " + username);
            }
        }

        final StringBuilder sb = new StringBuilder();
        sb.append("--" + BOUNDARY);
        sb.append(CRLF);
        
        
        OutputStream out = null;
        
        if (!useWorkerServlet) {
            String workerName = null;
            int workerId = 0;
            
            try {
                workerId = Integer.parseInt(workerNameOrId);
            } catch (NumberFormatException e) {
                workerName = workerNameOrId;
            }
            
            if (workerName == null) {
                sb.append("Content-Disposition: form-data; name=\"workerId\"");
                sb.append(CRLF);
                sb.append(CRLF);
                sb.append(workerId);
            } else {
                sb.append("Content-Disposition: form-data; name=\"workerName\"");
                sb.append(CRLF);
                sb.append(CRLF);
                sb.append(workerName);
            }
            sb.append(CRLF);
            
            sb.append("--" + BOUNDARY);
            sb.append(CRLF);
        }

        sb.append("Content-Disposition: form-data; name=\"datafile\"");
        sb.append("; filename=\"");
        // don't care about the actual file name for now...
        sb.append("noname.dat");
        
        sb.append("\"");
        sb.append(CRLF);
        sb.append("Content-Type: application/octet-stream");
        sb.append(CRLF);
        sb.append("Content-Transfer-Encoding: binary");
        sb.append(CRLF);
        sb.append(CRLF);

        urlConn.addRequestProperty("Content-Type",
                "multipart/form-data; boundary=" + BOUNDARY);
        urlConn.addRequestProperty("Content-Length", String.valueOf(
                sb.toString().length() + BOUNDARY.length() + 8-1));
        
        out = urlConn.getOutputStream();
                
        out.write(sb.toString().getBytes());
        out.write(data);
        
        out.write(("\r\n--" + BOUNDARY + "--\r\n").getBytes());
        out.flush();
        
        // Get the response
        final InputStream in = urlConn.getInputStream();
        final ByteArrayOutputStream os = new ByteArrayOutputStream();
        int len;
        final byte[] buf = new byte[1024];
        while ((len = in.read(buf)) > 0) {
            os.write(buf, 0, len);
        }
        os.close();
        out.close();
        in.close();
        
        // Take stop time
        final long estimatedTime = System.nanoTime() - startTime;
        final long timeInMillis = TimeUnit.NANOSECONDS.toMillis(estimatedTime);
        
        return timeInMillis;
    }

}
