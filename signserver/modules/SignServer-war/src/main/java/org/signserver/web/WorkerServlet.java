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

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

/**
 * Servlet handling requests addressed to a specific worker using a
 * URL of the form /signserver/worker/<worker name>
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class WorkerServlet extends HttpServlet {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            WorkerServlet.class);

	private static final String PROCESS_SERVLET_URL = "/process";
	private static final String WORKERNAME_PROPERTY_OVERRIDE = "workerNameOverride";
	private static final String WORKER_URI_START = "/signserver/worker/";
	
	private String parseWorkerName(HttpServletRequest req) {
		final String requestURI = req.getRequestURI();
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("Parsing request: " + requestURI);
		}

		if (requestURI.length() >= WORKER_URI_START.length() &&
				WORKER_URI_START.equals(requestURI.substring(0, WORKER_URI_START.length()))) {
			final String namePart = requestURI.substring(WORKER_URI_START.length());
			
			// if the parts after /worker/ starts with another / then just reject the URL
			if (namePart.length() > 0 && namePart.charAt(0) == '/') {
				return null;
			}
			
			return namePart;
		}
				
		return null;
	}
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		final String workerName = parseWorkerName(req);
		
		if (workerName == null) {
			// give a 404 error
			resp.sendError(HttpServletResponse.SC_NOT_FOUND, "No worker specified");
		} else {
			req.setAttribute(WORKERNAME_PROPERTY_OVERRIDE, workerName);
			// dispatch the message to the GeneralProcessServlet
			ServletContext context = getServletContext();
			RequestDispatcher dispatcher =
					context.getRequestDispatcher(PROCESS_SERVLET_URL);
			
			if (LOG.isDebugEnabled()) {
				LOG.debug("Forwarding request to: " + PROCESS_SERVLET_URL);
			}
			
			dispatcher.forward(req, resp);
		}
			
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		doGet(req, resp);
	}

}
