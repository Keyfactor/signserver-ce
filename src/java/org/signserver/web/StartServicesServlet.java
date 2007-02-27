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

import javax.ejb.CreateException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.signserver.ejb.IServiceTimerSessionLocalHome;

/**
 * Servlet used to start services by calling the ServiceTimerSession.load() at startup<br>
 *
 * 
 * 
 * @version $Id: StartServicesServlet.java,v 1.1 2007-02-27 16:18:21 herrvendil Exp $
 */
public class StartServicesServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(StartServicesServlet.class);
    
    /**
     * Method used to remove all active timers
	 * @see javax.servlet.GenericServlet#destroy()
	 */
	public void destroy() {		
        log.info("Destroy, Sign Server shutdown.");
        
        log.debug(">destroy calling ServiceSession.unload");
        try {
			getServiceHome().create().unload();
		} catch (CreateException e) {
			log.error(e);
		} catch (IOException e) {
			log.error(e);
	    }
		super.destroy();
	}


    private IServiceTimerSessionLocalHome servicehome = null;
 
    private synchronized IServiceTimerSessionLocalHome getServiceHome() throws IOException {
        try{
            if(servicehome == null){
            	servicehome = (IServiceTimerSessionLocalHome)ServiceLocator.getInstance().getLocalHome(IServiceTimerSessionLocalHome.COMP_NAME);
            }
          } catch(Exception e){
             throw new java.io.IOException("Authorization Denied");
          }
          return servicehome;
    }
      

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
		
        log.info("Init, Sign Server startup.");

        log.debug(">init calling ServiceSession.load");
        try {
			getServiceHome().create().load();
		} catch (CreateException e) {
			log.error("Error init ServiceSession: ", e);
		} catch (IOException e) {
			log.error("Error init ServiceSession: ", e);
	    }
		

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
