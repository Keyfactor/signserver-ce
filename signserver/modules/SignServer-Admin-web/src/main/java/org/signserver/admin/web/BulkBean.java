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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.WorkerConfig;
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
public class BulkBean {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(BulkBean.class);

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private String workerIds;
    private List<Integer> workerIdsList;

    private final Map<Integer, Boolean> selectedIds = new HashMap<>();
    private Map<Integer, Boolean> selectedIDsForActivation;

    private List<Worker> workers;

    private String activatePassword;

    private List<SelectItem> availableWorkersMenu;

    private String previous;

    /**
     * Creates a new instance of WorkersManagedBean
     */
    public BulkBean() {

    }

    public AdminWebSessionBean getWorkerSessionBean() {
        return workerSessionBean;
    }

    public String getWorkerIds() {
        return workerIds;
    }

    public void setWorkerIds(String workerIds) {
        this.workerIds = workerIds;
    }

    public AuthenticationBean getAuthBean() {
        return authBean;
    }

    public void setAuthBean(AuthenticationBean authBean) {
        this.authBean = authBean;
    }

    public String getPrevious() {
        return previous;
    }

    public void setPrevious(String previous) {
        this.previous = previous;
    }

    protected List<Integer> getWorkerIdsList() {
        if (workerIdsList == null) {
            workerIdsList = new ArrayList<>();
            if (workerIds != null) {
                String[] split = workerIds.split(",");
                for (String s : split) {
                    s = s.trim();
                    if (!s.isEmpty()) {
                        try {
                            workerIdsList.add(Integer.valueOf(s.trim()));
                        } catch (NumberFormatException ex) {
                            LOG.warn("Dropping non-numeric worker ID from selection: " + ex.getMessage());
                        }
                    }
                }
            }
        }
        return workerIdsList;
    }
    
    public int getWorkerIdByName(String workerName) throws AdminNotAuthorizedException {
        int workerId = workerSessionBean.getWorkerId(authBean.getAdminCertificate(), workerName);
        if (workerId == 0) {
            return -1;
        } else {
            return workerId;
        }
    }
    
    public Worker getWorker(int workerId) throws AdminNotAuthorizedException {
        WorkerConfig config = workerSessionBean.getCurrentWorkerConfig(authBean.getAdminCertificate(), workerId);
        String name = config.getProperty("NAME");
        boolean exists = true;
        if (name == null) {
            name = "Not Found";
            exists = false;
        }
        return new Worker(workerId, exists, name, config.getProperties());
    }

    public List<Worker> getWorkers() throws AdminNotAuthorizedException {
        if (workers == null) {
            workers = new ArrayList<>();
            for (int id : getWorkerIdsList()) {
                Worker newWorker = getWorker(id);
                workers.add(newWorker);
                selectedIds.put(id, newWorker.isExisting());
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
        return selectedIds;
    }
    
    /**
     * This method returns an altered selected ID-list with the non-cryptoworkers removed
     */
    public Map<Integer, Boolean> getSelectedIdsForActivation() throws AdminNotAuthorizedException {
       if (selectedIDsForActivation == null) {
           selectedIDsForActivation = new HashMap<>();
            for (int id: selectedIds.keySet()) {
                selectedIDsForActivation.put(id, getWorker(id).isHasCrypto());
            }
        } 
        return selectedIDsForActivation;
    }

    public List<Worker> getSelectedWorkers() throws AdminNotAuthorizedException {
        return getRelevantSelectedWorkers(selectedIds);
    }
    
    public List<Worker> getSelectedWorkersForActivation() throws AdminNotAuthorizedException {
        return getRelevantSelectedWorkers(selectedIDsForActivation);
    }
    
    public List<Worker> getRelevantSelectedWorkers(Map<Integer, Boolean> selectedIDMap) throws AdminNotAuthorizedException {
     final ArrayList<Worker> results = new ArrayList<>(selectedIDMap.size());
        for (Worker worker : getWorkers()) {
            if (Boolean.TRUE.equals(selectedIDMap.get(worker.getId()))) {
                results.add(worker);
            }
        }
        return results;
    }

    public String activateAction() throws AdminNotAuthorizedException {
        for (Worker worker : getSelectedWorkersForActivation()) {
            try {
                workerSessionBean.activateSigner(authBean.getAdminCertificate(), new WorkerIdentifier(worker.getId()), activatePassword);
                selectedIds.remove(worker.getId());
                worker.setError("");
                worker.setSuccess("Activated");
            } catch (CryptoTokenAuthenticationFailureException | CryptoTokenOfflineException | InvalidWorkerIdException ex) {
                worker.setError("Failed: " + ex.getMessage());
            }
        }

        if (selectedIds.isEmpty()) {
            return "workers?faces-redirect=true&amp;includeViewParams=true&amp;" + "selected=" + StringUtils.join(getWorkerIdsList(), ",");
        } else {
            return "";
        }
    }

    public String deactivateAction() throws AdminNotAuthorizedException {
        for (Worker worker : getSelectedWorkersForActivation()) {
            try {
                workerSessionBean.deactivateSigner(authBean.getAdminCertificate(), new WorkerIdentifier(worker.getId()));
                selectedIds.remove(worker.getId());
                worker.setError("");
                worker.setSuccess("Deactivated");
            } catch (CryptoTokenOfflineException | InvalidWorkerIdException ex) {
                worker.setError("Failed: " + ex.getMessage());
            }
        }

        if (selectedIds.isEmpty()) {
            return "workers?faces-redirect=true&amp;includeViewParams=true&amp;" + "selected=" + StringUtils.join(getWorkerIdsList(), ",");
        } else {
            return "";
        }
    }
    
    public String enableAction() throws AdminNotAuthorizedException {
        for (Worker worker : getSelectedWorkers()) {
            try {
               workerSessionBean.setWorkerProperty(authBean.getAdminCertificate(), worker.getId(), DISABLED, "FALSE");
               workerSessionBean.reloadConfiguration(authBean.getAdminCertificate(), worker.getId());
               selectedIds.remove(worker.getId());
               worker.setError("");
               worker.setSuccess("Enabled");
            } catch (AdminNotAuthorizedException ex) {
                worker.setError("Failed: " + ex.getMessage());
            }
        }

        if (selectedIds.isEmpty()) {
            return "workers?faces-redirect=true&amp;includeViewParams=true&amp;" + "selected=" + StringUtils.join(getWorkerIdsList(), ",");
        } else {
            return "";
        }
        
    }
    
     public String disableAction() throws AdminNotAuthorizedException {
        for (Worker worker : getSelectedWorkers()) {
            try {
               workerSessionBean.setWorkerProperty(authBean.getAdminCertificate(), worker.getId(), DISABLED, "TRUE");
               workerSessionBean.reloadConfiguration(authBean.getAdminCertificate(), worker.getId());
               selectedIds.remove(worker.getId());
               worker.setError("");
               worker.setSuccess("Disabled");
            } catch (AdminNotAuthorizedException ex) {
                worker.setError("Failed: " + ex.getMessage());
            }
        }

        if (selectedIds.isEmpty()) {
            return "workers?faces-redirect=true&amp;includeViewParams=true&amp;" + "selected=" + StringUtils.join(getWorkerIdsList(), ",");
        } else {
            return "";
        }
        
    }

    public List<SelectItem> getAvailableWorkersMenu() throws AdminNotAuthorizedException {
        if (availableWorkersMenu == null) {
            availableWorkersMenu = new ArrayList<>();
            availableWorkersMenu.add(new SelectItem("--", ""));
            // XXX: Should be some better API to get all the worker names without loading all config
            for (Integer id : getWorkerSessionBean().getAllWorkers(getAuthBean().getAdminCertificate())) {
                Properties config = getWorkerSessionBean().getCurrentWorkerConfig(getAuthBean().getAdminCertificate(), id).getProperties();
                final String name = config.getProperty("NAME", String.valueOf(id));
                availableWorkersMenu.add(new SelectItem(name + " (" + id + ")", name));
            }
        }
        return availableWorkersMenu;
    }

    public String getBackLink() {
        if ("worker".equals(previous)) {
            return "worker?id=" + getWorkerIdsList().get(0);
        } else if ("worker-configuration".equals(previous)) {
            return "worker-configuration?id=" + getWorkerIdsList().get(0);
        } else if ("cryptotoken".equals(previous)) {
            return "worker-cryptotoken?id=" + getWorkerIdsList().get(0);
        } else {
            return "workers?selected=" + StringUtils.join(getWorkerIdsList(), ",");
        }
    }
    
    public String getBackToCryptoTokenLink(List<String> keys) {
        final StringBuilder sb = new StringBuilder();
        final List<Integer> ids = getWorkerIdsList();
        sb.append("worker-cryptotoken?id=").append(ids.isEmpty() ? "" : ids.get(0));
        if (keys != null && !keys.isEmpty()) {
            for (String key : keys) {
                sb.append("&amp;selected=").append(key); // TODO: URLEncode
            }
        }
        return sb.toString();
    }
}
