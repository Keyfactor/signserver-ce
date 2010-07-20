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

import javax.ejb.EJB;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.signserver.common.CompileTimeSettings;
import org.signserver.ejb.interfaces.IServiceTimerSession;
import org.signserver.ejb.interfaces.IServiceTimerSession.ILocal;
import org.signserver.ejb.interfaces.IStatusRepositorySession;

/**
 * Servlet used to start services by calling the ServiceTimerSession.load() at
 * startup.
 * 
 * @version $Id$
 */
public class StartServicesServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(StartServicesServlet.class);

    @EJB
    private IServiceTimerSession.ILocal timedServiceSession;

    @EJB
    private IStatusRepositorySession.ILocal statusRepositorySession;

    private IServiceTimerSession.ILocal getTimedServiceSession(){
    	if(timedServiceSession == null){
    		try{
    		  Context context = new InitialContext();
    		  timedServiceSession = (ILocal) context.lookup(IServiceTimerSession.ILocal.JNDI_NAME);
    		}catch(NamingException e){
    			log.error(e);
    		}
    	}

    	return timedServiceSession;
    }

    private IStatusRepositorySession.ILocal getStatusRepositorySession() {
        if (statusRepositorySession == null) {
            try {
                Context context = new InitialContext();

                statusRepositorySession = (IStatusRepositorySession.ILocal) 
                        context.lookup(
                            IStatusRepositorySession.ILocal.JNDI_NAME);
            } catch (NamingException e) {
                log.error(e);
            }
        }
        return statusRepositorySession;
    }

    /**
     * Method used to remove all active timers
     * @see javax.servlet.GenericServlet#destroy()
     */
    public void destroy() {
        log.info("Destroy,  " + CompileTimeSettings.getInstance().getProperty(
                CompileTimeSettings.SIGNSERVER_VERSION) + " shutdown.");

        log.debug(">destroy calling ServiceSession.unload");

        getTimedServiceSession().unload(0);

        super.destroy();
    }

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        log.info("Init, " + CompileTimeSettings.getInstance().getProperty(
                CompileTimeSettings.SIGNSERVER_VERSION) + " startup.");

        log.debug(">init calling ServiceSession.load");
        
        // Start the timed services session
        getTimedServiceSession().load(0);

        // Instantiate the status repository session and also set a value
        getStatusRepositorySession().setProperty("INIT",
                String.valueOf(System.currentTimeMillis()));

    } // init

    public void doPost(HttpServletRequest req, HttpServletResponse res)
            throws IOException, ServletException {
        log.debug(">doPost()");
        doGet(req, res);
        log.debug("<doPost()");
    } //doPost

    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        log.debug(">doGet()");
        res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Servlet doesn't support requests is only loaded on startup.");
        log.debug("<doGet()");
    } // doGet
}
