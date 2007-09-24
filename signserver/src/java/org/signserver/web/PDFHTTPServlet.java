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

import javax.ejb.EJBException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.IllegalSignRequestException;
import org.signserver.common.SignTokenOfflineException;
import org.signserver.ejb.SignServerSessionLocal;
import org.signserver.ejb.SignServerSessionLocalHome;

 

/**
 * PDFHTTPServlet
 * 
 * Processes PDF signing Requests over HTTP
 * 
 * Use the request parameter 'signerId' to specify the PDF signer.
 * 
 * @author Tomas Gustavsson, based on TSAHTTPServlet by Philip Vendil
 * @version $Id: PDFHTTPServlet.java,v 1.2 2007-09-24 11:37:52 anatom Exp $
 */

public class PDFHTTPServlet extends HttpServlet {
	
	private static final long serialVersionUID = 1L;

	private static Logger log = Logger.getLogger(PDFHTTPServlet.class);
	
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
        int signerId = 1;
        if(req.getParameter(SIGNERID_PROPERTY_NAME) != null){
        	signerId = Integer.parseInt(req.getParameter(SIGNERID_PROPERTY_NAME));
        	log.debug("Found a signerid in the request");
        }
        log.debug("Using signerId: "+signerId);
                 
        String remoteAddr = req.getRemoteAddr();
        log.info("Recieved PDF sign request for signer " + signerId+", from ip "+remoteAddr);
        
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
        log.debug("Received PDF bytes of length: "+inbytes.length);
        
        Random rand = new Random();        
        int requestId = rand.nextInt();
        
        GenericSignResponse signResponse = null;
        try {
			signResponse = (GenericSignResponse) getSignSession().signData(signerId, new GenericSignRequest(requestId, inbytes),(X509Certificate) clientCertificate, remoteAddr);
		} catch (IllegalSignRequestException e) {
			 throw new ServletException(e);
		} catch (SignTokenOfflineException e) {
			 throw new ServletException(e);
	    }
		
		if(signResponse.getRequestID() != requestId){
			throw new ServletException("Error in signing operation, response id didn't match request id");
		}
		byte[] pdfbytes =  (byte[])signResponse.getSignedData();
		
		res.setContentType("application/pdf'");
		res.setContentLength(pdfbytes.length);
		res.getOutputStream().write(pdfbytes);
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
        res.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "PDF signer only supports POST");
        log.debug("<doGet()");        
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
