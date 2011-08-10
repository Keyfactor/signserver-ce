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
import java.util.HashMap;
import java.util.Map;

import javax.ejb.EJB;
import javax.naming.NamingException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.signserver.common.CompileTimeSettings;
import org.signserver.common.ServiceLocator;
import org.signserver.ejb.interfaces.IServiceTimerSession;
import org.signserver.ejb.interfaces.IStatusRepositorySession;
import org.signserver.server.log.ISystemLogger;
import org.signserver.server.log.SystemLoggerException;
import org.signserver.server.log.SystemLoggerFactory;

/**
 * Servlet used to start services by calling the ServiceTimerSession.load() at
 * startup.
 * 
 * @version $Id$
 */
public class StartServicesServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    
    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(StartServicesServlet.class);
    
    /** SystemLogger for this class. */
    private static final ISystemLogger AUDITLOG = SystemLoggerFactory
            .getInstance().getLogger(StartServicesServlet.class);

    @EJB
    private IServiceTimerSession.IRemote timedServiceSession;

    @EJB
    private IStatusRepositorySession.IRemote statusRepositorySession;

    private IServiceTimerSession.IRemote getTimedServiceSession(){
    	if(timedServiceSession == null) {
            try {
                timedServiceSession = ServiceLocator.getInstance().lookupRemote(
                        IServiceTimerSession.IRemote.class);
            } catch (NamingException e) {
                LOG.error(e);
            }
    	}

    	return timedServiceSession;
    }

    private IStatusRepositorySession.IRemote getStatusRepositorySession() {
        if (statusRepositorySession == null) {
            try {
                statusRepositorySession = ServiceLocator.getInstance()
                        .lookupRemote(IStatusRepositorySession.IRemote.class);
            } catch (NamingException e) {
                LOG.error(e);
            }
        }
        return statusRepositorySession;
    }

    /**
     * Method used to remove all active timers
     * @see javax.servlet.GenericServlet#destroy()
     */
    public void destroy() {
        final String version = CompileTimeSettings.getInstance().getProperty(
                CompileTimeSettings.SIGNSERVER_VERSION);

        LOG.info("Destroy,  " + version + " shutdown.");

        try {
            final Map<String, String> fields = new HashMap<String, String>();
            fields.put(ISystemLogger.LOG_EVENT, "SHUTDOWN");
            fields.put(ISystemLogger.LOG_VERSION, version);
            AUDITLOG.log(fields);
        } catch (SystemLoggerException ex) {
            LOG.error("Audit log error", ex);
        }

        LOG.debug(">destroy calling ServiceSession.unload");

        getTimedServiceSession().unload(0);

        super.destroy();
    }

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        final String version = CompileTimeSettings.getInstance().getProperty(
                CompileTimeSettings.SIGNSERVER_VERSION);
        
        LOG.info("Init, " + version + " startup.");

        try {
            final Map<String, String> fields = new HashMap<String, String>();
            fields.put(ISystemLogger.LOG_EVENT, "STARTUP");
            fields.put(ISystemLogger.LOG_VERSION, version);
            AUDITLOG.log(fields);
        } catch (SystemLoggerException ex) {
            LOG.error("Audit log error", ex);
        }

        LOG.debug(">init calling ServiceSession.load");
        
        // Start the timed services session
        getTimedServiceSession().load(0);

        // Instantiate the status repository session and also set a value
        getStatusRepositorySession().setProperty("INIT",
                String.valueOf(System.currentTimeMillis()));

    } // init

    public void doPost(HttpServletRequest req, HttpServletResponse res)
            throws IOException, ServletException {
        LOG.debug(">doPost()");
        doGet(req, res);
        LOG.debug("<doPost()");
    } //doPost

    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        LOG.debug(">doGet()");
        res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Servlet doesn't support requests is only loaded on startup.");
        LOG.debug("<doGet()");
    } // doGet
}
