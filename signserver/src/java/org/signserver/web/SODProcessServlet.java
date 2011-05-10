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

package org.signserver.web;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.ejbca.util.Base64;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.RequestContext;
import org.signserver.common.SODSignRequest;
import org.signserver.common.SODSignResponse;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IWorkerSession;



/**
 * SODProcessServlet is a Servlet that takes data group hashes from a htto post and puts them in a Map for passing
 * to the MRTD SOD Signer. It uses the worker configured by either workerId or workerName parameters from the request, defaulting to workerId 1.
 * 
 * It will create a SODSignRequest that is sent to the worker and expects a SODSignResponse back from the signer.
 * This is not located in the mrtdsod module package because it has to be available at startup to map urls.
 * 
 * @author Markus Kilas
 * @version $Id$
 */
public class SODProcessServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final String CONTENT_TYPE_BINARY = "application/octet-stream";
    private static final String CONTENT_TYPE_TEXT = "text/plain";

    private static final Logger log = Logger.getLogger(SODProcessServlet.class);

    private static final String DISPLAYCERT_PROPERTY_NAME = "displayCert";
    private static final String DOWNLOADCERT_PROPERTY_NAME = "downloadCert";
    private static final String WORKERID_PROPERTY_NAME = "workerId";
    private static final String WORKERNAME_PROPERTY_NAME = "workerName";
    private static final String DATAGROUP_PROPERTY_NAME = "dataGroup";
    /** Specifies if the fields are encoded in any way */
    private static final String ENCODING_PROPERTY_NAME = "encoding";
    /** Default, values will be base64 decoded before use */
    private static final String ENCODING_BASE64 = "base64";
    /** if encoding = binary values will not be base64 decoded before use */
    private static final String ENCODING_BINARY = "binary";

    private IWorkerSession.ILocal workersession;

    private IWorkerSession.ILocal getWorkerSession() {
        if (workersession == null) {
            try {
                Context context = new InitialContext();
                workersession = (org.signserver.ejb.interfaces.IWorkerSession.ILocal) context.lookup(IWorkerSession.ILocal.JNDI_NAME);
            } catch (NamingException e) {
                log.error(e);
            }
        }

        return workersession;
    }

    @Override
    public void init(ServletConfig config) {
    }

    /**
     * handles http post
     *
     * @param req servlet request
     * @param res servlet response
     *
     * @throws IOException input/output error
     * @throws ServletException error
     */
    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        if(log.isTraceEnabled()) {
            log.trace(">doPost()");
        }

        int workerId = 1;

        String name = req.getParameter(WORKERNAME_PROPERTY_NAME);
        if(name != null){
            log.debug("Found a signerName in the request: "+name);
            workerId = getWorkerSession().getWorkerId(name);
        }
        String id = req.getParameter(WORKERID_PROPERTY_NAME);
        if(id != null){
            log.debug("Found a signerId in the request: "+id);
            workerId = Integer.parseInt(id);
        }

        String remoteAddr = req.getRemoteAddr();

        // If the command is to display the signer certificate, print it.
        String displayCert = req.getParameter(DISPLAYCERT_PROPERTY_NAME);
        String downloadCert = req.getParameter(DOWNLOADCERT_PROPERTY_NAME);
        if ( (displayCert != null) && (displayCert.length() > 0) ) {
            log.info("Recieved display cert request for worker " + workerId + ", from ip " + remoteAddr);
        	displaySignerCertificate(res, workerId);
        } else if ( (downloadCert != null) && (downloadCert.length() > 0) ) {
        	log.info("Recieved download cert request for worker " + workerId + ", from ip " + remoteAddr);
        	sendSignerCertificate(res, workerId);
        } else {
        	// If the command is to process the signing request, do that.
            log.info("Recieved HTTP process request for worker " + workerId + ", from ip " + remoteAddr);

            boolean base64Encoded = true;
            String encoding = req.getParameter(ENCODING_PROPERTY_NAME);
            if(encoding != null && !"".equals(encoding)) {
                if(ENCODING_BINARY.equalsIgnoreCase(encoding)) {
                    base64Encoded = false;
                }   
            }
            if(log.isDebugEnabled()) {
                log.debug("Base64Encoded="+base64Encoded);
            }

            // Collect all [dataGroup1, dataGroup2, ..., dataGroupN]
            Map<Integer, byte[]> dataGroups = new HashMap<Integer, byte[]>(16);
            Enumeration en = req.getParameterNames();
            while(en.hasMoreElements()) {
                Object o = en.nextElement();
                if(o instanceof String) {
                    String key = (String) o;
                    if(key.startsWith(DATAGROUP_PROPERTY_NAME)) {
                        try {
                            Integer dataGroupId = new Integer(key.substring(DATAGROUP_PROPERTY_NAME.length()));
                            if ( (dataGroupId > -1) && (dataGroupId < 17) ) {
                                String dataStr = req.getParameter(key);
                                if ((dataStr != null) && (dataStr.length() > 0)) {
                                	byte[] data = dataStr.getBytes();
                                	if (log.isDebugEnabled()) {
                                    	log.debug("Adding data group "+key);
                                    	if (log.isTraceEnabled()) {
                                        	log.trace("with value "+dataStr);                            		
                                    	}
                                	}
                                    dataGroups.put(dataGroupId, base64Encoded ? Base64.decode(data) : data);
                                }                        	
                            } else {
                            	if (log.isDebugEnabled()) {
                            		log.debug("Ignoring data group "+dataGroupId);
                            	}
                            }
                        } catch(NumberFormatException ex) {
                            log.warn("Field does not start with \"" + DATAGROUP_PROPERTY_NAME + "\" and ends with a number: \"" + key + "\"");
                        }
                    }
                }
            }

            if(dataGroups.size() == 0) {
                throw new ServletException("Missing dataGroup fields in request");
            }

            if(log.isDebugEnabled()) {
                log.debug("Received number of dataGroups: " + dataGroups.size());
            }

            // Get the client certificate, if any is passed in an https exchange, to be used for client authentication
            Certificate clientCertificate = null;
            Certificate[] certificates = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
            if (certificates != null) {
                clientCertificate = certificates[0];
            }

            Random rand = new Random();
            int requestId = rand.nextInt();

            SODSignRequest signRequest = new SODSignRequest(requestId, dataGroups);
            SODSignResponse response = null;
            try {
                response = (SODSignResponse) getWorkerSession().process(workerId, signRequest, new RequestContext((X509Certificate) clientCertificate, remoteAddr));
            } catch (IllegalRequestException e) {
                throw new ServletException(e);
            } catch (CryptoTokenOfflineException e) {
                throw new ServletException(e);
            } catch (SignServerException e) {
                throw new ServletException(e);
            }

            if (response.getRequestID() != requestId) {
                throw new ServletException("Error in process operation, response id didn't match request id");
            }
            byte[] processedBytes = (byte[]) response.getProcessedData();

            res.setContentType(CONTENT_TYPE_BINARY);
            res.setContentLength(processedBytes.length);
            res.getOutputStream().write(processedBytes);
            res.getOutputStream().close();        	
        }


        log.debug("<doPost()");
    } //doPost

    private void displaySignerCertificate(final HttpServletResponse response,
            final int workerId) throws IOException {
        log.debug(">displaySignerCertificate()");
        Certificate cert = null;
        try {
            cert = getWorkerSession().getSignerCertificate(workerId);
        } catch (CryptoTokenOfflineException ignored) {}
        response.setContentType(CONTENT_TYPE_TEXT);
        if (cert == null) {
            response.getWriter().print(
                    "No signing certificate found for worker with id "
                    + workerId);
        } else {
            response.getWriter().print(cert);
        }
        log.debug("<displaySignerCertificate()");
    }

    private void sendSignerCertificate(final HttpServletResponse response,
            final int workerId) throws IOException {
        log.debug(">sendSignerCertificate()");
        Certificate cert = null;
        try {
            cert = getWorkerSession().getSignerCertificate(workerId);
        } catch (CryptoTokenOfflineException ignored) {}
        try {
            if (cert == null) {
                response.getWriter().print(
                        "No signing certificate found for worker with id "
                        + workerId);
            } else {
                byte[] bytes;
                bytes = cert.getEncoded();
                response.setContentType(CONTENT_TYPE_BINARY);
                response.setHeader("Content-Disposition", "filename=cert.crt");
                response.setContentLength(bytes.length);
                response.getOutputStream().write(bytes);
                response.getOutputStream().close();
            }
        } catch (CertificateEncodingException e) {
            log.error("Error encoding certificate: ", e);
            response.getWriter().print("Error encoding certificate: "
                    + e.getMessage());
        }
        log.debug("<sendSignerCertificate()");
    }

    /**
     * handles http get
     *
     * @param req servlet request
     * @param res servlet response
     *
     * @throws IOException input/output error
     * @throws ServletException error
     * @throws
     */
    public void doGet(HttpServletRequest req, HttpServletResponse res) throws java.io.IOException, ServletException {
        log.debug(">doGet()");
        doPost(req, res);
        log.debug("<doGet()");
    } // doGet

}
