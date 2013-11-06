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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Properties;

import java.util.List;
import javax.ejb.EJB;
import javax.persistence.EntityManager;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.ui.web.pub.cluster.IHealthCheck;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.healthcheck.HealthCheckUtils;
import org.signserver.server.nodb.FileBasedDatabaseManager;

/**
 * SignServer Health Checker. 
 * 
 * Does the following system checks.
 * 
 * Not about to run out if memory (configurable through web.xml with param "MinimumFreeMemory")
 * Database connection can be established.
 * All SignerTokens are active if not set as offline.
 * 
 * If a maintenance file has been configured during build, it can be used to enable maintenance mode.
 * When enabled, none of the above system checks are performed, instead a down-for-maintenance message is returned.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class SignServerHealthCheck implements IHealthCheck {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            SignServerHealthCheck.class);
    
    @EJB
    private IWorkerSession.ILocal signserversession;
    
    private int minfreememory;
    private String checkDBString;
    private String maintenanceFile;
    private String maintenancePropertyName;
    private EntityManager em;

    private IWorkerSession.ILocal getWorkerSession() {
        return signserversession;
    }

    @Override
    public void init(final ServletConfig config, final EntityManager em) {
        minfreememory = Integer.parseInt(config.getInitParameter("MinimumFreeMemory")) * 1024 * 1024;
        checkDBString = config.getInitParameter("checkDBString");
        maintenanceFile = config.getInitParameter("MaintenanceFile");
        maintenancePropertyName = config.getInitParameter("MaintenancePropertyName");
        this.em = em;
        if (LOG.isDebugEnabled()) {
            final StringBuilder buff = new StringBuilder();
            buff.append("Health check configured with:\n")
                    .append("minfreeememory: ").append(minfreememory).append("\n")
                    .append("checkDBString: ").append(checkDBString).append("\n")
                    .append("maintenancePropertyName: ").append(maintenancePropertyName).append("\n")
                    .append("entityManager: ").append(em);
            LOG.debug(buff.append(buff));
        }
        initMaintenanceFile();
    }

    @Override
    public String checkHealth(HttpServletRequest request) {
        final LinkedList<String> errors = new LinkedList<String>();
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Starting HealthCheck health check requested by : " + request.getRemoteAddr());
        }
        
        errors.addAll(checkMaintenance());
        
        // Perform further checks unless Down for maintenance
        if (errors.size() == 0) { 
            if (FileBasedDatabaseManager.getInstance().isUsed()) {
                LOG.debug("Checking file based database");
                errors.addAll(FileBasedDatabaseManager.getInstance().getFatalErrors());
            } else {
                LOG.debug("Checking real database");
                errors.addAll(HealthCheckUtils.checkDB(em, checkDBString));
            }
            
            if (errors.size() == 0) {
                errors.addAll(HealthCheckUtils.checkMemory(minfreememory));
                errors.addAll(checkSigners());
            }
        }
        
        // Render as text
        final StringBuilder buff = new StringBuilder();
        final String result;
        if (errors.size() == 0) {
            result = null;
        } else {
            for (final String error : errors) {
                buff.append(error).append("\n");
            }
            result = buff.toString();
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("HealthCheck result : " + result);
        }
        
        return result;
    }

    private List<String> checkSigners() {
        final LinkedList<String> result = new LinkedList<String>();
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
                            result.add("Worker " + workerStatus.getWorkerId() + ": " + error);
                        }
                    }
                }

            } catch (InvalidWorkerIdException e) {
                LOG.error(e.getMessage(), e);
            }
        }
        return result;
    }
    
	private List<String> checkMaintenance() {
        final LinkedList<String> result = new LinkedList<String>();
		if (StringUtils.isEmpty(maintenanceFile)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Maintenance file not specified, node will be monitored");
            }
		} else {
            File maintFile = new File(maintenanceFile);
            InputStream in = null;

            try {
                in = new FileInputStream(maintFile);
                final Properties maintenanceProperties = new Properties();
                maintenanceProperties.load(in);
                final String maintenancePropertyValue = maintenanceProperties.getProperty(maintenancePropertyName);
                if (maintenancePropertyValue == null) {
                LOG.info("Could not find property " + maintenancePropertyName + " in " + maintenanceFile +
                        ", will continue to monitor this node");
                } else if (Boolean.TRUE.toString().equalsIgnoreCase(maintenancePropertyValue)) {
                    result.add("MAINT: " + maintenancePropertyName);
                }
            } catch (IOException e) {
                result.add("MAINT: maintenance property file could not be read");
                LOG.error("Could not read Maintenance File. Expected to find file at: " + maintFile.getAbsolutePath());
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
        return result;
	}
	
	private void initMaintenanceFile() {
		if (StringUtils.isEmpty(maintenanceFile)) {
			LOG.debug("Maintenance file not specified, node will be monitored");
		} else {
			Properties maintenanceProperties = new Properties();
			File maintFile = new File(maintenanceFile);
			InputStream in = null;
			try {
				in = new FileInputStream(maintFile);
				maintenanceProperties.load(in);
			} catch (IOException e) {
				LOG.error("Could not read Maintenance File. Expected to find file at: " +
						maintFile.getAbsolutePath());
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
