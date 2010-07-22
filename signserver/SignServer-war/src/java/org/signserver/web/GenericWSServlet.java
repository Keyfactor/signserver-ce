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

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Random;

import javax.ejb.EJB;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextAttributeEvent;
import javax.servlet.ServletContextAttributeListener;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.genericws.GenericWSRequest;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.CertificateClientCredential;

/**
 * A special servlet used to support custom Jax-WS WebServices in
 * MAR modules. I.e instead of implementing a Worker it is possible
 * to just implement a JAX-WS WebService. This servlet does two
 * things.
 *   1. Extracts the worker name/id from the URL, signserver/ws/<name/id>/<servicename>
 *   2. Forwards the request/response objects to the worker.
 * 
 * @author Philip Vendil 8 okt 2008
 *
 * @version $Id$
 */

public class GenericWSServlet extends HttpServlet implements ServletContextAttributeListener, ServletContextListener{

    private static final long serialVersionUID = 1L;
	
    private static final Logger LOG = Logger.getLogger(
                GenericWSServlet.class);

    private Random rand = new Random();
	
    public void init(ServletConfig servletConfig) throws ServletException {
        super.init(servletConfig);        
    }



    protected void doPost( HttpServletRequest request, HttpServletResponse response) throws ServletException {
       forwardRequest(GenericWSRequest.REQUESTTYPE_POST, request, response, getServletContext());
    }

    protected void doGet( HttpServletRequest request, HttpServletResponse response)
        throws ServletException {
    	
    	forwardRequest(GenericWSRequest.REQUESTTYPE_GET, request, response, getServletContext());
    }
    
    protected void doPut( HttpServletRequest request, HttpServletResponse response)
        throws ServletException {
    	forwardRequest(GenericWSRequest.REQUESTTYPE_PUT, request, response, getServletContext());
    }
        
    protected void doDelete( HttpServletRequest request, HttpServletResponse response)
        throws ServletException {
    	forwardRequest(GenericWSRequest.REQUESTTYPE_DEL, request, response, getServletContext());
    }
    
    /**
     * Main method that forwards the HTTP request to a given worker.
     * 
     * 
     * @param requestType on of GenericWSRequest.REQUESTTYPE_ constants
     * @param request the HTTP request
     * @param response the HTTP response.
     * @throws ServletException 
     */
    private void forwardRequest(int requestType, HttpServletRequest request, HttpServletResponse response, ServletContext servletContext) throws ServletException{
    	
        if(GenericWSRequest.REQUESTTYPE_CONTEXT_INIT != requestType &&
                GenericWSRequest.REQUESTTYPE_CONTEXT_DESTROYED != requestType) {

            int workerId = getWorkerId(request);
            if(workerId == 0){
                    throw new ServletException("Error, couldn't parse worker name or id from request URI : " + request.getRequestURI());
            }

            String remoteAddr = request.getRemoteAddr();


            //
            Certificate clientCertificate = null;
            Certificate[] certificates = (X509Certificate[]) request.getAttribute( "javax.servlet.request.X509Certificate" );
            if(certificates != null){
                    clientCertificate = certificates[0];
            }
            RequestContext requestContext = new RequestContext(
                    (X509Certificate) clientCertificate, remoteAddr);

            if (clientCertificate instanceof X509Certificate) {
                final X509Certificate cert = (X509Certificate) clientCertificate;
                CertificateClientCredential credential
                        = new CertificateClientCredential(
                        cert.getSerialNumber().toString(16),
                        cert.getIssuerDN().getName());
                requestContext.put(RequestContext.CLIENT_CREDENTIAL, rand);
            }

            int requestId = rand.nextInt();

            GenericWSRequest wsreq = new GenericWSRequest(requestId,requestType,request,response,getServletConfig(), servletContext);
            try {
                    getWorkerSession().process(workerId, wsreq, requestContext);
            } catch (IllegalRequestException e) {
                    throw new ServletException(e);
            } catch (CryptoTokenOfflineException e) {
                    throw new ServletException(e);
            } catch (SignServerException e) {
                    throw new ServletException(e);
            }
        }
    }
    
    /**
     * Method checking the URI and parses the worker name or worker id
     * from it to know to which worker to forward the WS call to.
     * @param request the http request
     * @return the workerId or 0 if no valid worker id could be parsed.
     */
    private int getWorkerId(HttpServletRequest request){
    	int retval =0;
    	
    	String requestURI = request.getRequestURI();
    	String[] splittedURI = requestURI.split("/");
    	if(splittedURI.length >2){
    		String workerPart = splittedURI[splittedURI.length-2];    		
    		try{
    			retval = Integer.parseInt(workerPart);
    		}catch(NumberFormatException e){}
    		
    		if(retval == 0){
    			retval = getWorkerSession().getWorkerId(workerPart);
    		}
    	}
    	
    	return retval;
    }


    @EJB
    private IWorkerSession.ILocal workersession;
	
    private IWorkerSession.ILocal getWorkerSession(){
    	if(workersession == null){
    		try{
    		  Context context = new InitialContext();
    		  workersession =  (org.signserver.ejb.interfaces.IWorkerSession.ILocal) context.lookup(IWorkerSession.ILocal.JNDI_NAME);
    		}catch(NamingException e){
    			LOG.error(e);
    		}
    	}
    	
    	return workersession;
    }

	public void attributeAdded(ServletContextAttributeEvent arg0) {
		// Do Nothing		
	}

	public void attributeRemoved(ServletContextAttributeEvent arg0) {
		// Do Nothing		
	}

	public void attributeReplaced(ServletContextAttributeEvent arg0) {
		// Do Nothing		
	}

	public void contextDestroyed(ServletContextEvent event) {
		try {
			forwardRequest(GenericWSRequest.REQUESTTYPE_CONTEXT_DESTROYED, null, null, event.getServletContext());
		} catch (ServletException e) {
			LOG.error(e);
		}		
	}

	public void contextInitialized(ServletContextEvent event) {
		try {
			forwardRequest(GenericWSRequest.REQUESTTYPE_CONTEXT_INIT, null, null, event.getServletContext());
		} catch (ServletException e) {
			LOG.error(e);
		}
	}
	

}
