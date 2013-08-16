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
package org.signserver.client.cli.defaultimpl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.Map;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;

/**
 * Docuement validator using the HTTP protocol.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class HTTPDocumentValidator extends AbstractDocumentValidator {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(HTTPDocumentValidator.class);
    
    public static final String CRLF = "\r\n";
    private static final String BASICAUTH_AUTHORIZATION = "Authorization";
    private static final String BASICAUTH_BASIC = "Basic";
    private static final String BOUNDARY = "------------------signserver";
    
    private URL processServlet;
    private String workerName;
    private int workerId;
    private String username;
    private String password;

    public HTTPDocumentValidator(final URL processServlet,
            final String workerName, final String username,
            final String password) {
        this.processServlet = processServlet;
        this.workerName = workerName;
        this.workerId = 0;
        this.username = username;
        this.password = password;
    }
    
    public HTTPDocumentValidator(final URL processServlet,
            final int workerId, final String username,
            final String password) {
        this.processServlet = processServlet;
        this.workerName = null;
        this.workerId = workerId;
        this.username = username;
        this.password = password;
    }
    
    @Override
    protected void doValidate(byte[] data, String encoding, final OutputStream out, final Map<String, Object> requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException, IOException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending validation request "
                    + " containing data of length " + data.length + " bytes"
                    + " to worker " + workerName);
        }

        InputStream in = null;
        OutputStream outStream = null;
        
        try {
            final URLConnection conn = processServlet.openConnection();
            
            conn.setDoOutput(true);
            conn.setAllowUserInteraction(false);

            if (username != null && password != null) {
                conn.setRequestProperty(BASICAUTH_AUTHORIZATION, 
                        BASICAUTH_BASIC + " "
                        + new String(Base64.encode((username + ":" + password).getBytes())));
            }
            
            final StringBuilder sb = new StringBuilder();
            sb.append("--" + BOUNDARY);
            sb.append(CRLF);
            
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
            
            sb.append("Content-Disposition: form-data; name=\"processType\"");
            sb.append(CRLF);
            sb.append(CRLF);
            sb.append("validateDocument");
            sb.append(CRLF);
            sb.append("--" + BOUNDARY);
            sb.append(CRLF);
            sb.append("Content-Disposition: form-data; name=\"datafile\"");
            sb.append("; filename=\"");
            if (requestContext.get("FILENAME") == null) {
                sb.append("noname.dat");
            } else {
                sb.append(requestContext.get("FILENAME"));
            }
            sb.append("\"");
            sb.append(CRLF);
            
            sb.append("Content-Type: application/octet-stream");
            sb.append(CRLF);
            sb.append("Content-Transfer-Encoding: binary");
            sb.append(CRLF);
            sb.append(CRLF);

            conn.addRequestProperty("Content-Type",
                    "multipart/form-data; boundary=" + BOUNDARY);
           
            outStream = conn.getOutputStream();
            
            outStream.write(sb.toString().getBytes());
            outStream.write(data);
            
            outStream.write(("\r\n--" + BOUNDARY + "--\r\n").getBytes());
            outStream.flush();
            
            // Get the response
            in = conn.getInputStream();
            final ByteArrayOutputStream os = new ByteArrayOutputStream();
            int len;
            final byte[] buf = new byte[1024];
            while ((len = in.read(buf)) > 0) {
                os.write(buf, 0, len);
            }
            os.close();
            
            // read string from response
            final String response = os.toString();
            
            if ("VALID".equals(response)) {
                out.write(("Valid: " + Boolean.TRUE.booleanValue()).getBytes());
            } else {
                out.write(("Valid: " + Boolean.FALSE.booleanValue()).getBytes());
            }
            out.write("\n".getBytes());            
            
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        } finally {
            if (out != null) {
                try {
                    outStream.close();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }
        }
    }

}
