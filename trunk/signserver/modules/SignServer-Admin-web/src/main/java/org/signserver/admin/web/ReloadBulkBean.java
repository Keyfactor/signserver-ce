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
import java.util.Properties;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.signserver.common.WorkerConfig;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class ReloadBulkBean extends BulkBean {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ReloadBulkBean.class);

    private static final String RELOAD_ALL = "all";
    private static final String RELOAD_SELECTED = "selected";
    private String reloadTarget;

    private List<MyWorker> myWorkers;

    /**
     * Creates a new instance of WorkersManagedBean
     */
    public ReloadBulkBean() {

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

    public String reloadAction() throws AdminNotAuthorizedException {
        //FacesMessage errorMessage = new FacesMessage("Test error");
        //errorMessage.setSeverity(FacesMessage.SEVERITY_ERROR);
        //FacesContext.getCurrentInstance().addMessage(null, errorMessage);

        if (RELOAD_ALL.equals(reloadTarget)) {
            getWorkerSessionBean().reloadConfiguration(getAuthBean().getAdminCertificate(), 0);

            return "workers?faces-redirect=true&amp;includeViewParams=true&amp;" + "selected=" + StringUtils.join(getWorkerIdsList(), ",");
        } else {
            for (MyWorker worker : getMySelectedWorkers()) {
                try {
                    getWorkerSessionBean().reloadConfiguration(getAuthBean().getAdminCertificate(), worker.getId());
                    worker.setError(null);
                    worker.setSuccess("Reloaded");
                    getSelectedIds().remove(worker.getId());
                } catch (AdminNotAuthorizedException ex) {
                    worker.setError(ex.getMessage());
                    worker.setSuccess(null);
                }
            }

            if (getSelectedIds().isEmpty()) {
                return "workers?faces-redirect=true&amp;includeViewParams=true&amp;" + "selected=" + StringUtils.join(getWorkerIdsList(), ",");
            } else {
                return "";
            }
        }
    }

    public String getRELOAD_ALL() {
        return RELOAD_ALL;
    }

    public String getRELOAD_SELECTED() {
        return RELOAD_SELECTED;
    }

    public String getReloadTarget() throws AdminNotAuthorizedException {
        if (reloadTarget == null) {
            reloadTarget = getMyWorkers().isEmpty() ? RELOAD_ALL : RELOAD_SELECTED;
        }
        return reloadTarget;
    }

    public void setReloadTarget(String reloadTarget) {
        this.reloadTarget = reloadTarget;
    }

    public static class MyWorker extends Worker {

        public MyWorker(int id, boolean exists, String name, Properties config) {
            super(id, exists, name, config);
        }

    }
}
