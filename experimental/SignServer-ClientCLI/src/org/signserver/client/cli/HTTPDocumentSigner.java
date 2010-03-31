/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.signserver.client.cli;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.net.URLConnection;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import javax.naming.NamingException;
import org.apache.log4j.Logger;
import org.signserver.client.api.ISignServerWorker;
import org.signserver.client.api.SigningAndValidationEJB;
import org.signserver.client.api.SigningAndValidationWS;
import org.signserver.client.api.SigningAndValidationWSBalanced;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;


/**
 *
 * @author markus
 */
public class HTTPDocumentSigner extends AbstractDocumentSigner {
    public static final String CRLF = "\r\n";

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(HTTPDocumentSigner.class);

    private static final String BOUNDARY = "------------------signserver";

    private String workerName;

    private URL processServlet;

    private Random random = new Random();

    public HTTPDocumentSigner(final URL processServlet,
            final String workerName) {
        this.processServlet = processServlet;
        this.workerName = workerName;
    }

    protected void doSign(final byte[] data, final String encoding,
            final OutputStream out) throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException,
                IOException {

//        final int requestId = random.nextInt();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending sign request "
                    + " containing data of length " + data.length + " bytes"
                    + " to worker " + workerName);
        }

        // Take start time
        final long startTime = System.nanoTime();

        final Response response = sendRequest(processServlet, workerName, data);

        // Take stop time
        final long estimatedTime = System.nanoTime() - startTime;

       

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Got sign response "
                    + "with signed data of length %d bytes.",
                    response.getData().length));

            // Write the signed data
            out.write(response.getData());

            LOG.info("Processing took "
                    + TimeUnit.NANOSECONDS.toMillis(estimatedTime) + " ms");
        } else {
            throw new SignServerException("Unexpected response type: "
                    + response.getClass().getName());
        }
    }

    private Response sendRequest(final URL processServlet,
            final String workerName, final byte[] data) {
        
        OutputStream out = null;
        InputStream in = null;
        try {
            final URLConnection conn = processServlet.openConnection();
            conn.setDoOutput(true);
            conn.setAllowUserInteraction(false);
            
            final StringBuilder sb = new StringBuilder();
            sb.append("--" + BOUNDARY);
            sb.append(CRLF);
            sb.append("Content-Disposition: form-data; name=\"workerName\"");
            sb.append(CRLF);
            sb.append(CRLF);
            sb.append(workerName);
            sb.append(CRLF);
            sb.append("--" + BOUNDARY);
            sb.append(CRLF);
            sb.append("Content-Disposition: form-data; name=\"datafile\"; filename=\"document.dat\"");
            sb.append(CRLF);
            sb.append("Content-Type: application/octet-stream");
            sb.append(CRLF);
            sb.append("Content-Transfer-Encoding: binary");
            sb.append(CRLF);
            sb.append(CRLF);

            conn.addRequestProperty("Content-Type",
                    "multipart/form-data; boundary=" + BOUNDARY);
            conn.addRequestProperty("Content-Length", String.valueOf(
                    sb.toString().length() + BOUNDARY.length() + 8-1));
            
            out = conn.getOutputStream();
            
            out.write(sb.toString().getBytes());
            out.write(data);
            out.write(new String("\r\n--" + BOUNDARY + "--\r\n").getBytes());
            out.flush();

            // Get the response
            in = conn.getInputStream();
            final ByteArrayOutputStream os = new ByteArrayOutputStream();
            int len;
            final byte[] buf = new byte[1024];
            while ((len = in.read(buf)) > 0) {
                os.write(buf, 0, len);
            }
            os.close();

            return new Response(os.toByteArray());
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        } finally {
            if (out != null) {
                try {
                    out.close();
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

    private static class Response {

        private byte[] data;

        public Response(byte[] data) {
            this.data = data;
        }

        public byte[] getData() {
            return data;
        }
        
    }

}
