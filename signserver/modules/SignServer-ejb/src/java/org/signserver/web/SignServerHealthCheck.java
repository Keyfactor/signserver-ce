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


import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;
import java.util.Properties;

import java.util.List;
import javax.ejb.EJB;
import javax.naming.NamingException;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
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
    private String maintenanceFile;
    private String maintenancePropertyName;

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
        maintenanceFile = config.getInitParameter("MaintenanceFile");
        maintenancePropertyName = config.getInitParameter("MaintenancePropertyName");
        
        initMaintenanceFile();
    }

    public String checkHealth(HttpServletRequest request) {
        LOG.debug("Starting HealthCheck health check requested by : " + request.getRemoteAddr());
        
        StringBuilder sb = new StringBuilder();
        checkMaintenance(sb);
		if( sb.length()>0 ) { 
			// if Down for maintenance do not perform more checks
			return sb.toString(); 
		}
        
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
    
    
	private void checkMaintenance(final StringBuilder sb) {
		if (StringUtils.isEmpty(maintenanceFile)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Maintenance file not specified, node will be monitored");
            }
			return;
		} 
		InputStream in = null;
		try {
			in = new FileInputStream(maintenanceFile);
	        final Properties maintenanceProperties = new Properties();
			maintenanceProperties.load(in);
            final String maintenancePropertyValue = maintenanceProperties.getProperty(maintenancePropertyName);
            if (maintenancePropertyValue == null) {
               LOG.info("Could not find property " + maintenancePropertyName+ " in " + maintenanceFile+ ", will continue to monitor this node");
            } else if (Boolean.TRUE.toString().equalsIgnoreCase(maintenancePropertyValue)) {
                sb.append("MAINT: ").append(maintenancePropertyName);
            }
		} catch (IOException e) {
	        if (LOG.isDebugEnabled()) {
	            LOG.debug("Could not read Maintenance File. Expected to find file at: "+ maintenanceFile);
	        }
			return;
		} finally {
			if (in != null) {
				try {
					in.close();					
				} catch (IOException e) {
					LOG.error("Error closing file: ", e);
				}
			}
		}
	}
	
	private void initMaintenanceFile() {
		if (StringUtils.isEmpty(maintenanceFile)) {
			LOG.debug("Maintenance file not specified, node will be monitored");
		} else {
			Properties maintenanceProperties = new Properties();
			InputStream in = null;
			try {
				in = new FileInputStream(maintenanceFile);
				maintenanceProperties.load(in);
			} catch (IOException e) {
				LOG.debug("Could not read Maintenance File. Expected to find file at: "+ maintenanceFile);
			} finally {
				if (in != null) {
					try {
						in.close();					
					} catch (IOException e) {
						LOG.error("Error closing file: ", e);
					}
				}
			}
		}
	}
}
