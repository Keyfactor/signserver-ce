package org.signserver.web.pub;

/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 


import java.io.IOException;
import java.util.Arrays;
import javax.persistence.EntityManager;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.signserver.common.SignServerUtil;
import org.signserver.web.pub.SameRequestRateLimiter;
import org.signserver.web.pub.cluster.IHealthCheck;
import org.signserver.web.pub.cluster.IHealthResponse;



/**
 * Servlet used to check the health of an EJBCA instance and can be used
 * to build a cluster using a loadbalancer.
 * 
 * This servlet should be configured with two init params:
 *   HealthCheckClassPath : containing the classpath to the IHealthCheck class to be used to check.
 *   HealthResponseClassPath : containing the classpath to the IHealthResponse class to be used 
 *   for the HTTPResponse
 * 
 * The loadbalancer or monitoring application should perform a GET request
 * to the url defined in web.xml.
 * 
 * This class was copied from the old EJBCA-util.
 *
 * @author Philip Vendil
 * @version $Id: HealthCheckServlet.java 6668 2008-11-28 16:28:44Z jeklund $
 */
public class HealthCheckServlet extends HttpServlet {
    private static final Logger log = Logger.getLogger(HealthCheckServlet.class);
    /** Internal localization of logs and errors */
    
    private IHealthCheck healthcheck = null;
    private IHealthResponse healthresponse = null;

    private String[] authIPs = null;
    private boolean allIPsAuth;
    
    private static final SameRequestRateLimiter<String> rateLimiter = new SameRequestRateLimiter<>();
    
    /** EntityManager is conditionally injected from web.xml. */
    private EntityManager em;
    
    /**
     * Servlet init
     *
     * @param config servlet configuration
     *
     * @throws ServletException on error
     */
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        try {
            // Install BouncyCastle provider
            SignServerUtil.installBCProvider();

            String authIPString = config.getInitParameter("AuthorizedIPs");
            if (authIPString != null) {
            	authIPs = authIPString.split(";");
            }

            if (Arrays.asList(authIPs).contains("ANY")) {
                log.info("All IP addresses authorized");
                allIPsAuth = true;
            }
            
            healthcheck = (IHealthCheck) HealthCheckServlet.class.getClassLoader().loadClass(config.getInitParameter("HealthCheckClassPath")).newInstance();
            healthcheck.init(config, em);
            
            healthresponse = (IHealthResponse) HealthCheckServlet.class.getClassLoader().loadClass(config.getInitParameter("HealthResponseClassPath")).newInstance();
            healthresponse.init(config);
            
        } catch( Exception e ) {
            throw new ServletException(e);
        }
    }

    /**
     * Handles HTTP POST
     *
     * @param request servlet request
     * @param response servlet response
     *
     * @throws IOException input/output error
     * @throws ServletException on error
     */
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException {
        log.trace(">doPost()");
        check(request, response);
        log.trace("<doPost()");
    }

    //doPost

    /**
     * Handles HTTP GET
     *
     * @param request servlet request
     * @param response servlet response
     *
     * @throws IOException input/output error
     * @throws ServletException on error
     */
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException {
        log.trace(">doGet()");
        check(request, response);
        log.trace("<doGet()");
    }
    
    private void check(HttpServletRequest request, HttpServletResponse response){
    	boolean authorizedIP = false;
    	String remoteIP = request.getRemoteAddr();
    	if (allIPsAuth) {
    	    authorizedIP = true;
    	} else {
    	    for (final String ip : authIPs) {
    	        if (remoteIP.equals(ip)) {
    	            authorizedIP = true;
    	        }
    	    }
    	}

    	if (authorizedIP) {
    	    final SameRequestRateLimiter<String>.Result result = rateLimiter.getResult();
    	    
    	    if (result.isFirst()) {
    	        try {
    	            result.setValue(healthcheck.checkHealth(request));
    	        } catch (Throwable t) {
    	            result.setError(t);
    	        }
    	    } else if (log.isDebugEnabled()) {
    	        log.debug("Re-using health check answer from first concurrent request for this request to conserve server load.");
    	    }
    	    healthresponse.respond(result.getValue(), response);
    	} else {
    	    if ((remoteIP == null) || (remoteIP.length() > 100) ) {
		remoteIP = "unknown";    			  
    	    }
    	    try {
    		response.sendError(HttpServletResponse.SC_UNAUTHORIZED,"ERROR : Healthcheck request received from a non authorized IP: "+remoteIP);
    	    } catch (IOException e) {
    	        log.error("ERROR : Problems generating unauthorized http response.");
    	    }
    	    log.error("Healthcheck request received from a non authorized IP: " + remoteIP);
    	}
    }

}


// HealthCheckServlet
