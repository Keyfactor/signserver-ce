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
import org.signserver.admin.common.config.RekeyUtil;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RenewKeyBulkBean extends BulkBean {

    private List<RenewKeyWorker> renewKeyWorkers;

    /**
     * Creates a new instance of WorkersManagedBean
     */
    public RenewKeyBulkBean() {

    }

    public List<RenewKeyWorker> getRenewKeyWorkers() throws AdminNotAuthorizedException {
        if (renewKeyWorkers == null) {
            renewKeyWorkers = new ArrayList<>();
            for (int id : getWorkerIdsList()) {
                WorkerConfig config = getWorkerSessionBean().getCurrentWorkerConfig(getAuthBean().getAdminCertificate(), id);
                String name = config.getProperty("NAME");
                boolean exists = true;
                if (name == null) {
                    name = "Not Found";
                    exists = false;
                }
                final String oldAlias = config.getProperty("DEFAULTKEY");
                final String keyAlg = config.getProperty("KEYALG");
                final String keySpec = config.getProperty("KEYSPEC");
                final String newAlias = oldAlias != null ? RekeyUtil.nextAliasInSequence(oldAlias) : null;
                renewKeyWorkers.add(new RenewKeyWorker(id, exists, name, config.getProperties(), oldAlias, keyAlg, keySpec, newAlias));

                // Select checkbox
                getSelectedIds().put(id, exists);
            }
        }
        return renewKeyWorkers;
    }

    public List<RenewKeyWorker> getSelectedRenewKeyWorkers() throws AdminNotAuthorizedException {
        final ArrayList<RenewKeyWorker> results = new ArrayList<>(getSelectedIds().size());
        for (RenewKeyWorker worker : getRenewKeyWorkers()) {
            if (Boolean.TRUE.equals(getSelectedIds().get(worker.getId()))) {
                results.add(worker);
            }
        }
        return results;
    }

    public String renewKeyAction() throws AdminNotAuthorizedException {
        //FacesMessage errorMessage = new FacesMessage("Test error");
        //errorMessage.setSeverity(FacesMessage.SEVERITY_ERROR);
        //FacesContext.getCurrentInstance().addMessage(null, errorMessage);

        for (RenewKeyWorker worker : getSelectedRenewKeyWorkers()) {

            String newAlias = null;
            try {
                // Generate key
                newAlias = getWorkerSessionBean().generateSignerKey(getAuthBean().getAdminCertificate(), new WorkerIdentifier(worker.getId()),
                        worker.getKeyAlgorithm(), worker.getKeySpecification(), worker.getNewKeyAlias(), "");

                if (newAlias == null) {
                    worker.setError("Could not generate key");
                    worker.setSuccess(null);
                } else {
                    worker.setError(null);
                    worker.setSuccess("Generated " + newAlias);
                }
            } catch (CryptoTokenOfflineException | InvalidWorkerIdException e) {
                worker.setError("Failed: " + e.getMessage());
                worker.setSuccess(null);
            }

            if (newAlias != null) {
                //LOG.debug("Created key " + newAlias + " for signer " + signerId);

                // Update key label
                getWorkerSessionBean().setWorkerProperty(getAuthBean().getAdminCertificate(), worker.getId(),
                        "NEXTCERTSIGNKEY", newAlias);

                // Reload configuration
                getWorkerSessionBean().reloadConfiguration(getAuthBean().getAdminCertificate(), worker.getId());

                //LOG.debug("Configured new key " + newAlias + " for signer " + signerId);
                getSelectedIds().remove(worker.getId());
            }
        }

        if (getSelectedIds().isEmpty()) {
            return "workers?faces-redirect=true&amp;includeViewParams=true&amp;" + "selected=" + StringUtils.join(getWorkerIdsList(), ",");
        } else {
            return "";
        }
    }

    public static class RenewKeyWorker extends Worker {

        private String oldKeyAlias;
        private String keyAlgorithm;
        private String keySpecification;
        private String newKeyAlias;

        public RenewKeyWorker(int id, boolean exists, String name, Properties config, String oldKeyAlias, String keyAlgorithm, String keySpecification, String newKeyAlias) {
            super(id, exists, name, config);
            this.oldKeyAlias = oldKeyAlias;
            this.keyAlgorithm = keyAlgorithm;
            this.keySpecification = keySpecification;
            this.newKeyAlias = newKeyAlias;
        }

        public String getOldKeyAlias() {
            return oldKeyAlias;
        }

        public void setOldKeyAlias(String oldKeyAlias) {
            this.oldKeyAlias = oldKeyAlias;
        }

        public String getKeyAlgorithm() {
            return keyAlgorithm;
        }

        public void setKeyAlgorithm(String keyAlgorithm) {
            this.keyAlgorithm = keyAlgorithm;
        }

        public String getKeySpecification() {
            return keySpecification;
        }

        public void setKeySpecification(String keySpecification) {
            this.keySpecification = keySpecification;
        }

        public String getNewKeyAlias() {
            return newKeyAlias;
        }

        public void setNewKeyAlias(String newKeyAlias) {
            this.newKeyAlias = newKeyAlias;
        }

    }
}
