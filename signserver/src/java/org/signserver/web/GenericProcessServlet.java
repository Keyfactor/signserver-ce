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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
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
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericServletRequest;
import org.signserver.common.GenericServletResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.ejb.interfaces.IWorkerSession;

 

/**
 * GenericProcessServlet is a general Servlet passing on it's request info to the worker configured by either
 * workerId or workerName parameters.
 * 
 * It will create a GenericServletRequest that is sent to the worker and expects a GenericServletResponse
 * sent back to the client.
 * 
 * 
 * @author Philip Vendil
 */

public class GenericProcessServlet extends HttpServlet {
	
	private static final long serialVersionUID = 1L;

	private static Logger log = Logger.getLogger(GenericProcessServlet.class);
	
	private static final String WORKERID_PROPERTY_NAME = "workerId";
	private static final String WORKERNAME_PROPERTY_NAME = "workerName";

	private IWorkerSession.ILocal workersession;
	
    private IWorkerSession.ILocal getWorkerSession(){
    	if(workersession == null){
    		try{
    		  Context context = new InitialContext();
    		  workersession =  (org.signserver.ejb.interfaces.IWorkerSession.ILocal) context.lookup(IWorkerSession.ILocal.JNDI_NAME);
    		}catch(NamingException e){
    			log.error(e);
    		}
    	}
    	
    	return workersession;
    }

	
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
    public void doPost(HttpServletRequest req, HttpServletResponse res)
        throws IOException, ServletException {
        log.debug(">doPost()");
        int workerId = 1;
        if(req.getParameter(WORKERNAME_PROPERTY_NAME) != null){
        	workerId = getWorkerSession().getWorkerId(req.getParameter(WORKERNAME_PROPERTY_NAME));
        	log.debug("Found a signerName in the request");
        }
        if(req.getParameter(WORKERID_PROPERTY_NAME) != null){
        	workerId = Integer.parseInt(req.getParameter(WORKERID_PROPERTY_NAME));
        	log.debug("Found a signerid in the request");
        }
        log.debug("Using signerId: "+workerId);
                 
        String remoteAddr = req.getRemoteAddr();
        log.info("Recieved HTTP process request for worker " + workerId+", from ip "+remoteAddr);
        
        // 
        Certificate clientCertificate = null;
       	Certificate[] certificates = (X509Certificate[]) req.getAttribute( "javax.servlet.request.X509Certificate" );
    	if(certificates != null){
    		clientCertificate = certificates[0];
    	}
    	// Limit the maximum size of input to 100MB (100*1024*1024)
    	log.debug("Received a request with length: "+req.getContentLength());
		if (req.getContentLength() > 104857600){
			log.error("Content length exceeds 100MB, not processed: "+req.getContentLength());
			throw new ServletException("Error. Maximum content lenght is 100MB.");
		}

    	// Get an input stream and read the pdf bytes from the stream
        InputStream in = req.getInputStream();
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        int len = 0;
        byte[] buf = new byte[1024];
        while ((len = in.read(buf)) > 0) {
            os.write(buf, 0, len);
        }
        in.close();
        os.close();
        byte[] inbytes = os.toByteArray();
        log.debug("Received bytes of length: "+inbytes.length);
        
        Random rand = new Random();        
        int requestId = rand.nextInt();

        GenericServletResponse response = null;
        try {
        	response = (GenericServletResponse) getWorkerSession().process(workerId, new GenericServletRequest(requestId, inbytes,req),new RequestContext((X509Certificate) clientCertificate, remoteAddr));
		} catch (IllegalRequestException e) {
			 throw new ServletException(e);
		} catch (CryptoTokenOfflineException e) {
			 throw new ServletException(e);
	    } catch (SignServerException e) {
	    	throw new ServletException(e);
		}
		
		if(response.getRequestID() != requestId){
			throw new ServletException("Error in process operation, response id didn't match request id");
		}
		byte[] processedBytes =  (byte[])response.getProcessedData();
		
		res.setContentType(response.getContentType());
		res.setContentLength(processedBytes.length);
		res.getOutputStream().write(processedBytes);
		res.getOutputStream().close();
        log.debug("<doPost()");
    } //doPost

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
    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        log.debug(">doGet()");
        doGet(req, res);
        log.debug("<doGet()");        
    } // doGet
	
	


}
