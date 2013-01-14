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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.ejb.EJB;
import javax.naming.NamingException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.signserver.common.CompileTimeSettings;
import org.signserver.common.FileBasedDatabaseException;
import org.signserver.common.ServiceLocator;
import org.signserver.ejb.interfaces.IServiceTimerSession;
import org.signserver.server.cesecore.AlwaysAllowLocalAuthenticationToken;
import org.signserver.server.log.SignServerEventTypes;
import org.signserver.server.log.SignServerModuleTypes;
import org.signserver.server.log.SignServerServiceTypes;
import org.signserver.server.nodb.FileBasedDatabaseManager;
import org.signserver.statusrepo.IStatusRepositorySession;
import org.signserver.statusrepo.common.NoSuchPropertyException;
import org.signserver.statusrepo.common.StatusEntry;
import org.signserver.statusrepo.common.StatusName;

/**
 * Servlet used to start services by calling the ServiceTimerSession.load() at
 * startup.
 * 
 * @version $Id$
 */
public class StartServicesServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    
    private static final String LOG_VERSION = "VERSION";
    
    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(StartServicesServlet.class);
    
    @EJB
    private IServiceTimerSession.IRemote timedServiceSession;

    @EJB
    private IStatusRepositorySession.IRemote statusRepositorySession;

    @EJB
    private SecurityEventsLoggerSessionLocal logSession;
    
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
    @Override
    public void destroy() {
        final String version = CompileTimeSettings.getInstance().getProperty(
                CompileTimeSettings.SIGNSERVER_VERSION);

        LOG.info("Destroy,  " + version + " shutdown.");
        
        // Try to unload the timers
        LOG.debug(">destroy calling ServiceSession.unload");
        try {
            getTimedServiceSession().unload(0);
        } catch (Exception ex) {
            LOG.info("Exception caught trying to cancel timers. This happens with some application servers: " + ex.getMessage());
        }

        super.destroy();
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        final CompileTimeSettings settings = CompileTimeSettings.getInstance();
        final String version = settings.getProperty(
                CompileTimeSettings.SIGNSERVER_VERSION);
        
        LOG.info("Init, " + version + " startup.");
      
        // Make a log row that EJBCA is starting
        AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("StartServicesServlet.init"));
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", "start services startup msg");
        details.put(LOG_VERSION, version);
        try {
            logSession.log(SignServerEventTypes.SIGNSERVER_STARTUP, EventStatus.SUCCESS, SignServerModuleTypes.SERVICE, SignServerServiceTypes.SIGNSERVER, admin.toString(), null, null, null, details);
        } catch (AuditRecordStorageException ex) {
            LOG.error("Logging", ex);
            throw new ServletException("Could not log", ex);
        }

        // Cancel old timers as we can not rely on them being cancelled at shutdown
        LOG.debug(">init calling ServiceSession.unload");
        getTimedServiceSession().unload(0);
        
        LOG.debug(">init FileBasedDataseManager");
        final FileBasedDatabaseManager nodb = FileBasedDatabaseManager.getInstance();
        if (nodb.isUsed()) {
            try {
                nodb.initialize();
            } catch (FileBasedDatabaseException ex) {
                throw new UnavailableException(ex.getMessage());
            }
            
            final List<String> fatalErrors = nodb.getFatalErrors();
            if (!fatalErrors.isEmpty()) {
                final StringBuilder buff = new StringBuilder();
                buff.append("Error initializing file based database manager: ");
                buff.append(fatalErrors);
                LOG.error(buff.toString());
                throw new UnavailableException(buff.toString());
            }
        }

        LOG.debug(">init calling ServiceSession.load");
        
        // Start the timed services session
        getTimedServiceSession().load(0);

        // Instantiate the status repository session and list all available status properties
        LOG.debug(">init StatusReposotorySession");
        try {
            getStatusRepositorySession().update(StatusName.SERVER_STARTED.name(), String.valueOf(System.currentTimeMillis()));
            for(Map.Entry<String, StatusEntry> entry : getStatusRepositorySession().getAllEntries().entrySet()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Status property: " + entry.getKey() + " = " + entry.getValue());
                }
            }
        } catch (NoSuchPropertyException ex) {
            throw new RuntimeException(ex);
        }
        
    } // init

    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse res)
            throws IOException, ServletException {
        LOG.debug(">doPost()");
        doGet(req, res);
        LOG.debug("<doPost()");
    } //doPost

    @Override
    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        LOG.debug(">doGet()");
        res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Servlet doesn't support requests is only loaded on startup.");
        LOG.debug("<doGet()");
    } // doGet
}
