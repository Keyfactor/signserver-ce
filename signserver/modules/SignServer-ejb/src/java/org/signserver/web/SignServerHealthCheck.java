package org.signserver.web;

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


import java.util.Iterator;
import java.util.List;
import javax.ejb.EJB;
import javax.naming.NamingException;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import org.apache.log4j.Logger;
import org.ejbca.ui.web.pub.cluster.IHealthCheck;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.ServiceLocator;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.healthcheck.HealthCheckUtils;

/**
 * SignServer Health Checker. 
 * 
 * Does the following system checks.
 * 
 * Not about to run out if memory (configurable through web.xml with param "MinimumFreeMemory")
 * Database connection can be established.
 * All SignerTokens are active if not set as offline.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class SignServerHealthCheck implements IHealthCheck {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            SignServerHealthCheck.class);
    
    @EJB
    private IGlobalConfigurationSession.IRemote globalConfigurationSession;
    
    @EJB
    private IWorkerSession.IRemote signserversession;
    
    private int minfreememory;
    private String checkDBString;

    private IGlobalConfigurationSession.IRemote getGlobalConfigurationSession() {
        if (globalConfigurationSession == null) {
            try {
                globalConfigurationSession = ServiceLocator.getInstance().lookupRemote(
                        IGlobalConfigurationSession.IRemote.class);
            } catch (NamingException e) {
                LOG.error(e);
            }
        }
        return globalConfigurationSession;
    }

    private IWorkerSession.IRemote getWorkerSession() {
        if (signserversession == null) {
            try {
                signserversession = ServiceLocator.getInstance().lookupRemote(IWorkerSession.IRemote.class);
            } catch (NamingException e) {
                LOG.error(e);
            }
        }
        return signserversession;
    }

    public void init(ServletConfig config) {
        minfreememory = Integer.parseInt(config.getInitParameter("MinimumFreeMemory")) * 1024 * 1024;
        checkDBString = config.getInitParameter("checkDBString");

    }

    public String checkHealth(HttpServletRequest request) {
        LOG.debug("Starting HealthCheck health check requested by : " + request.getRemoteAddr());
        String errormessage = "";

        errormessage += HealthCheckUtils.checkDB(checkDBString);
        if (errormessage.equals("")) {
            errormessage += HealthCheckUtils.checkMemory(minfreememory);
            errormessage += checkSigners();

        }

        if (errormessage.equals("")) {
            // everything seems ok.
            errormessage = null;
        }

        return errormessage;
    }

    private String checkSigners() {
        final StringBuilder sb = new StringBuilder();
        Iterator<Integer> iter = getWorkerSession().getWorkers(GlobalConfiguration.WORKERTYPE_PROCESSABLE).iterator();
        while (iter.hasNext()) {
            int processableId = ((Integer) iter.next()).intValue();

            try {
                WorkerStatus workerStatus = getWorkerSession().getStatus(processableId);
                if (workerStatus.isDisabled()) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Not checking worker " + processableId + " as it is disabled");
                    }
                } else {
                    final List<String> fatalErrors = workerStatus.getFatalErrors();
                    if (!fatalErrors.isEmpty()) {
                        for (String error : fatalErrors) {
                            sb.append("Worker ")
                                .append(workerStatus.getWorkerId())
                                .append(": ")
                                .append(error)
                                .append("\n");
                        }
                    }
                }

            } catch (InvalidWorkerIdException e) {
                LOG.error(e.getMessage(), e);
            }
        }
        if (sb.length() > 0) {
            LOG.error("Health check reports error:\n" + sb.toString());
        }
        return sb.toString();
    }
}
