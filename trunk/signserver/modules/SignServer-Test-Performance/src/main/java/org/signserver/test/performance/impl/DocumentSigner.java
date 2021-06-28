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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.apache.log4j.Logger;
import java.io.InputStream;
import java.net.HttpURLConnection;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.NullOutputStream;
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
    private final String processType;
    private final Random random;
    private final byte[] indata;
    private final File infile;

    private final String userPrefix;
    private final Integer userSuffixMin;
    private final Integer userSuffixMax;

    public DocumentSigner(final String url, final boolean useWorkerServlet, 
            final byte[] indata, final File infile, final String workerNameOrId, final String processType, final Random random,
            final String userPrefix, final Integer userSuffixMin, final Integer userSuffixMax) {
        this.url = url;
        this.useWorkerServlet = useWorkerServlet;
        this.indata = indata;
        this.infile = infile;
        this.workerNameOrId = workerNameOrId;
        this.processType = processType;
        this.random = random;
        this.userPrefix = userPrefix;
        this.userSuffixMin = userSuffixMin;
        this.userSuffixMax = userSuffixMax;
    }
    
    @Override
    public long run() throws FailedException {
        InputStream in = null;
        try {
            long size;
            if (indata == null) {
                in = new FileInputStream(infile);
                size = infile.length();
            } else {
                in = new ByteArrayInputStream(indata);
                size = indata.length;
            }
            return documentRequest(in, size);
        } catch (IOException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Could not create request", ex);
            }
            throw new FailedException("Could not create request: " + ex.getMessage());
        } finally {
            IOUtils.closeQuietly(in);
        }
    }
    
    /**
     * Issue a request to a documt signer as configured for the Task.
     * 
     * @return Run time (in ms).
     * @throws IOException
     */
    private long documentRequest(InputStream in, long size) throws IOException {
        URL url;
        HttpURLConnection urlConn;

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

        urlConn = (HttpURLConnection) url.openConnection();

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
        
        // processType
        sb.append("Content-Disposition: form-data; name=\"processType\"");
        sb.append(CRLF);
        sb.append(CRLF);
        sb.append(processType);
        sb.append(CRLF);
            
        sb.append("--" + BOUNDARY);
        sb.append(CRLF);

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

        final byte[] preData = sb.toString().getBytes("ASCII");
        final byte[] postData = ("\r\n--" + BOUNDARY + "--\r\n").getBytes("ASCII");
        
        if (size >= 0) {
            final long totalSize = (long) preData.length + size + (long) postData.length;
            urlConn.setFixedLengthStreamingMode(totalSize);
        }
        
        
        // Write the request: preData, data, postData
        out = urlConn.getOutputStream();
        out.write(preData);
        final long copied = IOUtils.copyLarge(in, out);
        if (copied != size) {
            throw new IOException("Expected file size of " + size + " but only read " + copied + " bytes");
        }
        out.write(postData);
        out.flush();
        
        try ( // Get the response
                InputStream inResp = urlConn.getInputStream(); NullOutputStream os = new NullOutputStream()) {
            int len;
            final byte[] buf = new byte[1024];
            while ((len = inResp.read(buf)) > 0) {
                os.write(buf, 0, len);
            }
        }
        out.close();
        
        // Take stop time
        final long estimatedTime = System.nanoTime() - startTime;
        final long timeInMillis = TimeUnit.NANOSECONDS.toMillis(estimatedTime);
        
        return timeInMillis;
    }

}
