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
package org.signserver.admin.web;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.WorkerConfig;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RemoveBulkBean extends BulkBean {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(RemoveBulkBean.class);

    private List<MyWorker> myWorkers;

    /**
     * Creates a new instance of WorkersManagedBean
     */
    public RemoveBulkBean() {

    }

    public List<MyWorker> getMyWorkers() throws AdminNotAuthorizedException {
        if (myWorkers == null) {
            myWorkers = new ArrayList<>();
            for (int id : getWorkerIdsList()) {
                WorkerConfig config = getWorkerSessionBean().getCurrentWorkerConfig(getAuthBean().getAdminCertificate(), id);
                String name = config.getProperty("NAME");
                boolean exists = true;
                if (name == null) {
                    name = "Not Found";
                    exists = false;
                }

                MyWorker worker = new MyWorker(id, exists, name, config.getProperties());
                myWorkers.add(worker);

                // Select checkbox
                getSelectedIds().put(id, exists);
            }
        }
        return myWorkers;
    }

    public List<MyWorker> getMySelectedWorkers() throws AdminNotAuthorizedException {
        final ArrayList<MyWorker> results = new ArrayList<>(getSelectedIds().size());
        for (MyWorker worker : getMyWorkers()) {
            if (Boolean.TRUE.equals(getSelectedIds().get(worker.getId()))) {
                results.add(worker);
            }
        }
        return results;
    }

    public String removeAction() throws AdminNotAuthorizedException {
        //FacesMessage errorMessage = new FacesMessage("Test error");
        //errorMessage.setSeverity(FacesMessage.SEVERITY_ERROR);
        //FacesContext.getCurrentInstance().addMessage(null, errorMessage);
        GlobalConfiguration globalConfiguration = getWorkerSessionBean().getGlobalConfiguration(getAuthBean().getAdminCertificate());

        for (MyWorker worker : getMySelectedWorkers()) {
            try {
                removeWorker(worker, globalConfiguration);
                worker.setError(null);
                worker.setSuccess("Removed");
                worker.setRemoved(true);
                getSelectedIds().remove(worker.getId());
            } catch (AdminNotAuthorizedException ex) {
                worker.setError(ex.getMessage());
                worker.setSuccess(null);
                worker.setRemoved(false);
            }
        }

        if (getSelectedIds().isEmpty()) {
            return "workers?faces-redirect=true";
        } else {
            return "";
        }
    }

    private void removeWorker(MyWorker worker, GlobalConfiguration gc) throws AdminNotAuthorizedException {
        // Remove global properties
        for (Map.Entry<Object, Object> entry : gc.getConfig().entrySet()) {
            if (entry.getKey() instanceof String) {
                String key = (String) entry.getKey();
                if (key.toUpperCase(Locale.ENGLISH).startsWith("GLOB.WORKER" + worker.getId())) {
                    key = key.substring("GLOB.".length());
                    if (getWorkerSessionBean().removeGlobalProperty(getAuthBean().getAdminCertificate(), GlobalConfiguration.SCOPE_GLOBAL, key)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("  Global property '" + key + "' removed successfully.");
                        }
                    } else {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("  Failed removing global property '" + key + "'.");
                        }
                    }
                }
            }
        }
        // Remove worker properties
        for (final String property : worker.getConfig().stringPropertyNames()) {
            if (getWorkerSessionBean().removeWorkerProperty(getAuthBean().getAdminCertificate(), worker.getId(), property)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("  Property '" + property + "' removed.");
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("  Error, the property '" + property + "' couldn't be removed.");
                }
            }
        }
        getWorkerSessionBean().reloadConfiguration(getAuthBean().getAdminCertificate(), worker.getId());
    }

    public static class MyWorker extends Worker {

        private boolean removed;

        public MyWorker(int id, boolean exists, String name, Properties config) {
            super(id, exists, name, config);
        }

        public boolean isRemoved() {
            return removed;
        }

        public void setRemoved(boolean removed) {
            this.removed = removed;
        }

    }
}
