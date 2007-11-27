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
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.SignServerException;
import org.signserver.ejb.interfaces.IWorkerSession;

 

/**
 * TSAHTTPServlet
 * 
 * Processes Time Stamp Requests over HTTP
 * 
 * Use the request parameter 'signerId' to specify the timestamp signer.
 * 
 * @author Philip Vendil
 * @version $Id: TSAHTTPServlet.java,v 1.6 2007-11-27 06:05:08 herrvendil Exp $
 */

public class TSAHTTPServlet extends HttpServlet {
	
	private static final long serialVersionUID = 1L;

	private static Logger log = Logger.getLogger(TSAHTTPServlet.class);
	

	private IWorkerSession.ILocal signserversession;
	
    private IWorkerSession.ILocal getSignServerSession(){
    	if(signserversession == null){
    		try{
    		  Context context = new InitialContext();
    		  signserversession =  (org.signserver.ejb.interfaces.IWorkerSession.ILocal) context.lookup(IWorkerSession.ILocal.JNDI_NAME);
    		}catch(NamingException e){
    			log.error(e);
    		}
    	}
    	
    	return signserversession;
    }
	
	private static final String SIGNERID_PROPERTY_NAME = "signerId";

	

	
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
        doGet(req, res);
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

        int signerId = 1;
        if(req.getParameter(SIGNERID_PROPERTY_NAME) != null){
        	signerId = Integer.parseInt(req.getParameter(SIGNERID_PROPERTY_NAME));
        }
                 
        log.debug("Recieved Timestamp request for signer " + signerId);
        
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

        TimeStampRequest timeStampRequest = new TimeStampRequest(req.getInputStream());
        
        Random rand = new Random();        
        int requestId = rand.nextInt();
        
        GenericSignResponse signResponse = null;
        try {
			signResponse = (GenericSignResponse) getSignServerSession().process(signerId, new GenericSignRequest(requestId, timeStampRequest),(X509Certificate) clientCertificate, req.getRemoteAddr());
		} catch (IllegalRequestException e) {
			 throw new ServletException(e);
		} catch (CryptoTokenOfflineException e) {
			 throw new ServletException(e);
	    } catch (SignServerException e) {
	    	throw new ServletException(e);
		}
		
		if(signResponse.getRequestID() != requestId){
			throw new ServletException("Error in signing operation, response id didn't match request id");
		}
		Object response =  signResponse.getProcessedData();
		
		TimeStampResponse timeStampResponse = null;
		if(response instanceof byte[]){
			
			try {
				timeStampResponse = new TimeStampResponse((byte[]) response);
			} catch (TSPException e) {
				throw new ServletException(e);
			}
		}else{
			timeStampResponse = (TimeStampResponse) response;
		}

		res.setContentType("application/timestamp-reply");
		res.setContentLength(timeStampResponse.getEncoded().length);
		res.getOutputStream().write(timeStampResponse.getEncoded());
		res.getOutputStream().close();
        

    } // doGet
	

}
