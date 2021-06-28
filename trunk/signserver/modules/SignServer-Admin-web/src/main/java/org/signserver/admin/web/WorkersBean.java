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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.ResourceBundle;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;
import static org.signserver.common.SignServerConstants.DISABLED;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class WorkersBean {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(WorkersBean.class);

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;
    
    @ManagedProperty("#{text}")
    private ResourceBundle text;

    private String workersRequestedSelected;
    private Map<Integer, Boolean> selectedIds;

    private List<Worker> workers;

    private String activatePassword;

    /**
     * Creates a new instance of WorkersManagedBean
     */
    public WorkersBean() {

    }

    public AuthenticationBean getAuthBean() {
        return authBean;
    }

    public void setAuthBean(AuthenticationBean authBean) {
        this.authBean = authBean;
    }

    public String getWorkersRequestedSelected() {
        return workersRequestedSelected;
    }

    public void setWorkersRequestedSelected(String workersRequestedSelected) {
        this.workersRequestedSelected = workersRequestedSelected;
    }

    @SuppressWarnings("UseSpecificCatch")
    public List<Worker> getWorkers() throws AdminNotAuthorizedException {
        if (workers == null) {
            workers = new ArrayList<>();
            for (int id : workerSessionBean.getAllWorkers(authBean.getAdminCertificate())) {
                Properties config = workerSessionBean.getCurrentWorkerConfig(authBean.getAdminCertificate(), id).getProperties();
                final String name = config.getProperty("NAME", String.valueOf(id));
                Worker w = new Worker(id, true, name, config);
                try {
                    boolean workerSetAsDisabled = config.getProperty(DISABLED, "FALSE").equalsIgnoreCase("TRUE");
                    if (workerSetAsDisabled) {
                        w.setStatus(text.getString("DISABLED"));
                    } else {
                        w.setStatus(workerSessionBean.getStatus(authBean.getAdminCertificate(),
                                new WorkerIdentifier(id)).getFatalErrors().isEmpty()
                                        ? text.getString("ACTIVE") : text.getString("OFFLINE"));
                    }
                } catch (Throwable ignored) { // NOPMD: We safe-guard for bugs in worker implementations and don't want the GUI to fail for those.
                    w.setStatus(text.getString("OFFLINE"));
                }

                workers.add(w);
            }
        }
        return workers;
    }

    public String getActivatePassword() {
        return activatePassword;
    }

    public void setActivatePassword(String activatePassword) {
        this.activatePassword = activatePassword;
    }

    public Map<Integer, Boolean> getSelectedIds() {
        if (selectedIds == null) {
            selectedIds = new HashMap<>();
            if (workersRequestedSelected != null) {
                String[] split = workersRequestedSelected.split(",");
                for (String s : split) {
                    try {
                        s = StringUtils.trim(s);
                        selectedIds.put(Integer.valueOf(s), Boolean.TRUE);
                    } catch (NumberFormatException ex) {
                        LOG.warn("Dropping non-numeric worker ID from selection: " + ex.getMessage());
                    }
                }
            }
        }
        return selectedIds;
    }

    public List<Worker> getSelectedWorkers() throws AdminNotAuthorizedException {
        final ArrayList<Worker> results = new ArrayList<>(selectedIds.size());
        for (Worker worker : getWorkers()) {
            if (Boolean.TRUE.equals(selectedIds.get(worker.getId()))) {
                results.add(worker);
            }
        }
        return results;
    }
    
    public void setText(ResourceBundle text) {
        this.text = text;
    }

    public String bulkAction(String page) {
        StringBuilder sb = new StringBuilder();
        sb.append(page);
        sb.append("?faces-redirect=true&amp;includeViewParams=true&amp;workers=");
        for (Map.Entry<Integer, Boolean> entry : getSelectedIds().entrySet()) {
            if (entry.getValue()) {
                sb.append(entry.getKey()).append(",");               
            }
        }
        return sb.toString();
    }

    public String activateStep2Action() throws AdminNotAuthorizedException {
        for (Worker worker : getSelectedWorkers()) {
            try {
                workerSessionBean.activateSigner(authBean.getAdminCertificate(), new WorkerIdentifier(worker.getId()), activatePassword);
                selectedIds.remove(worker.getId());
            } catch (CryptoTokenAuthenticationFailureException | CryptoTokenOfflineException | InvalidWorkerIdException ex) {
                worker.setError("Failed: " + ex.getMessage());
            }
        }

        if (selectedIds.isEmpty()) {
            return "workers";
        } else {
            return "";
        }
    }

}
