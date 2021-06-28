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

import org.signserver.web.common.ServletUtils;
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
public class GenericProcessWorkerServlet extends HttpServlet {

    private static final Logger LOG = Logger.getLogger(GenericProcessWorkerServlet.class);

    private static final String PROCESS_SERVLET_URL = "/process";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                    throws ServletException, IOException {
        final String workerURIStart =
                req.getServletContext().getContextPath() + "/worker/";
        final String workerName =
                ServletUtils.parseWorkerName(req, workerURIStart);

        if (workerName == null) {
            // give a 404 error
            resp.sendError(HttpServletResponse.SC_NOT_FOUND,
                           "No worker specified");
        } else {
            req.setAttribute(ServletUtils.WORKERNAME_PROPERTY_OVERRIDE,
                             workerName);
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
