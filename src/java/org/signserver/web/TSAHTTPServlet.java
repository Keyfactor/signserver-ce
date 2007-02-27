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

import javax.ejb.EJBException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.ejbca.core.ejb.ServiceLocator;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.IllegalSignRequestException;
import org.signserver.common.SignTokenOfflineException;
import org.signserver.ejb.SignServerSessionLocal;
import org.signserver.ejb.SignServerSessionLocalHome;

 

/**
 * TSAHTTPServlet
 * 
 * Processes Time Stamp Requests over HTTP
 * 
 * Use the request parameter 'signerId' to specify the timestamp signer.
 * 
 * @author Philip Vendil
 * @version $Id: TSAHTTPServlet.java,v 1.1 2007-02-27 16:18:21 herrvendil Exp $
 */

public class TSAHTTPServlet extends HttpServlet {
	
	private static final long serialVersionUID = 1L;

	private static Logger log = Logger.getLogger(TSAHTTPServlet.class);
	
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

        TimeStampRequest timeStampRequest = new TimeStampRequest(req.getInputStream());
        
        Random rand = new Random();        
        int requestId = rand.nextInt();
        
        GenericSignResponse signResponse = null;
        try {
			signResponse = (GenericSignResponse) getSignSession().signData(signerId, new GenericSignRequest(requestId, timeStampRequest),(X509Certificate) clientCertificate, req.getRemoteAddr());
		} catch (IllegalSignRequestException e) {
			 throw new ServletException(e);
		} catch (SignTokenOfflineException e) {
			 throw new ServletException(e);
	    }
		
		if(signResponse.getRequestID() != requestId){
			throw new ServletException("Error in signing operation, response id didn't match request id");
		}
		TimeStampResponse timeStampResponse = (TimeStampResponse) signResponse.getSignedData(); 

		res.setContentType("application/timestamp-reply");
		res.setContentLength(timeStampResponse.getEncoded().length);
		res.getOutputStream().write(timeStampResponse.getEncoded());
		res.getOutputStream().close();
        

    } // doGet
	

	
	private SignServerSessionLocal signsession = null;	
	private SignServerSessionLocal getSignSession(){
		if(signsession == null){

			try {			
				SignServerSessionLocalHome signhome = (SignServerSessionLocalHome) ServiceLocator.getInstance().getLocalHome(SignServerSessionLocalHome.COMP_NAME);
			    signsession = signhome.create();
			} catch (Exception e) {
				throw new EJBException(e);
			} 
			
		}
		
		return signsession;
	}
	
	

}
