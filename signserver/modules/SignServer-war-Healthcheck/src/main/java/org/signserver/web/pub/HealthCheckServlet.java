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
import jakarta.persistence.EntityManager;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;

import org.apache.log4j.Logger;
import org.signserver.common.ComponentLoader;
import org.signserver.common.SignServerUtil;
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

    // have one rate limiter per QueryParameter, since it customizes the response
    private static final ConcurrentHashMap<QueryParameters, SameRequestRateLimiter<String>> rateLimiter = new ConcurrentHashMap<>();
    
    /** EntityManager is conditionally injected from web.xml. */
    private EntityManager em;

    /**
     * I hold all the query parameters to customize the health check.
     * I can also be used as key in a map to allow for rate limiting
     * customized health checks.
     */
    public static class QueryParameters {
        final private Set<Integer> workerIds;
        private boolean dontCheckWorkers;

        public QueryParameters(HttpServletRequest request) throws ServletException {
            workerIds = new HashSet<>();

            if (ServletFileUpload.isMultipartContent(request)) {
                final ServletFileUpload upload =
                        new ServletFileUpload(new DiskFileItemFactory());

                try {
                    final List<FileItem> items = upload.parseRequest(request);

                    for (final FileItem item : items) {
                        if (item.isFormField() &&
                            "workerId".equals(item.getFieldName())) {
                            final String workerId = item.getString();

                            if ("none".equals(workerId)) {
                                dontCheckWorkers = true;
                                break;
                            }

                            try {
                                workerIds.add(Integer.valueOf(workerId));
                            } catch (NumberFormatException e) {
                                log.error("Illegal worker ID: " + workerId);
                            }
                        }
                    }
                } catch (FileUploadException e) {
                    throw new ServletException("Upload failed: ", e);
                }   
            } else {
                final String[] workerIdStrings = request.getParameterValues("workerId");

                if (workerIdStrings != null) {
                    for (final String workerId : workerIdStrings) {
                        /* if "none" is specified as a workerId parameter
                         * treat it as specifying no workers should be checked
                         */
                        if ("none".equalsIgnoreCase(workerId)) {
                            dontCheckWorkers = true;
                            break;
                        }

                        try {
                            workerIds.add(Integer.valueOf(workerId));
                        } catch (NumberFormatException e) {
                            log.error("Illegal worker ID: " + workerId);
                        }
                    }
                }
            }
        }

        /**
         * Determine if a given worker ID should be health checked.
         * 
         * @param workerId
         * @return True if worker should be included in health check
         */
        public boolean shouldCheckWorker(final int workerId) {
            return !dontCheckWorkers &&
                   (workerIds.contains(workerId) || workerIds.isEmpty());
        }

        /**
         * Determine if all worker checks should be skipped.
         *
         * @return True if all worker checks should be skipped 
         */
        public boolean isDontCheckWorkers() {
            return dontCheckWorkers;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + Arrays.hashCode(workerIds.toArray());

            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            QueryParameters other = (QueryParameters) obj;
            return Arrays.equals(workerIds.toArray(), other.workerIds.toArray());
        }

    }

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
            final ComponentLoader classLoaderHelper = new ComponentLoader();

            healthcheck = classLoaderHelper.load(config.getInitParameter("HealthCheckClassPath"), IHealthCheck.class, getClass().getClassLoader());
            healthcheck.init(config, em);

            healthresponse = classLoaderHelper.load(config.getInitParameter("HealthResponseClassPath"), IHealthResponse.class, getClass().getClassLoader());
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
    
    private void check(HttpServletRequest request, HttpServletResponse response) throws ServletException{
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
            final QueryParameters queryParameters = new QueryParameters(request);
            // if we've got multiple HealthChecks with the same query parameters at the same time, only do one
            final SameRequestRateLimiter<String>.Result result = rateLimiter
                .computeIfAbsent(queryParameters, t ->
                                 new SameRequestRateLimiter<>()).getResult();
    	    
    	    if (result.isFirst()) {
    	        try {
    	            result.setValue(healthcheck.checkHealth(request,
                                                            queryParameters));
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
