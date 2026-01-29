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
import java.util.HashSet;
import java.util.HashMap;


import jakarta.faces.view.ViewScoped;
import jakarta.inject.Named;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.signserver.admin.common.config.RekeyUtil;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.ReadOnlyWorkerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@Named
@ViewScoped
public class RenewKeyBulkBean extends BulkBean {

    private static final Logger LOG = Logger.getLogger(RenewKeyBulkBean.class);
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
                WorkerConfig config = getWorkerSessionBean().getCurrentWorkerConfig(loginBean.getAdminPrincipal(), id);
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
        final List<Integer> readOnlyWorkers = new ArrayList<>();

        if (validateMultiKeyGeneration())
            for (RenewKeyWorker worker : getSelectedRenewKeyWorkers()) {

                String newAlias = null;
                try {
                    // Generate key
                    newAlias = getWorkerSessionBean().generateSignerKey(loginBean.getAdminPrincipal(), new WorkerIdentifier(worker.getId()),
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

                try {
                    if (newAlias != null) {
                        //LOG.debug("Created key " + newAlias + " for signer " + signerId);

                        // Update key label
                        getWorkerSessionBean().setWorkerProperty(loginBean.getAdminPrincipal(), worker.getId(),
                                "NEXTCERTSIGNKEY", newAlias);

                        // Reload configuration
                        getWorkerSessionBean().reloadConfiguration(loginBean.getAdminPrincipal(), worker.getId());

                        //LOG.debug("Configured new key " + newAlias + " for signer " + signerId);
                        getSelectedIds().remove(worker.getId());
                    }
                } catch (ReadOnlyWorkerException ex) {
                    // If we reach here, adding the new key alias property has failed due to worker being read-only.
                    // Since key generation operation has gone through, the worker has already had its status updated with:
                    // worker.setError(null);
                    // worker.setSuccess("Generated " + newAlias);
                    // Meaning we do not have to take action in this catch clause.
                    // For debugging purposes we collect all read-only IDs
                    readOnlyWorkers.add(worker.getId());
                }
                LOG.warn("Key renewal was partially successful. The following workers: " + readOnlyWorkers + " are read-only and have not had their new key alias property updated.");
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
        private boolean selectAlgFromList = true;
        private boolean selectKeySpecFromList = true;
        private List<SelectItem> algMenuValues;
        private List<SelectItem> keySpecMenuValues;

        public RenewKeyWorker(int id, boolean exists, String name, Properties config, String oldKeyAlias, String keyAlgorithm, String keySpecification, String newKeyAlias) {
            super(id, exists, name, config);
            this.oldKeyAlias = oldKeyAlias;
            this.keyAlgorithm = keyAlgorithm;
            this.keySpecification = keySpecification;
            this.newKeyAlias = newKeyAlias;
            if (keyAlgorithm == null) {
                /* if KEYALG is not set, fallback to RSA as that is first in
                 * the dropdown menu
                 */
                this.keyAlgorithm = "RSA";
            }
        }

        public String getOldKeyAlias() {
            return oldKeyAlias;
        }

        public void setOldKeyAlias(String oldKeyAlias) {
            this.oldKeyAlias = StringUtils.trim(oldKeyAlias);
        }

        public String getKeyAlgorithm() {
            return keyAlgorithm;
        }

        public void setKeyAlgorithm(String keyAlgorithm) {
            final String newKeyAlgorithm = StringUtils.trim(keyAlgorithm);

            if (!this.keyAlgorithm.equals(newKeyAlgorithm)) {
                keySpecMenuValues = null;
                this.keyAlgorithm = StringUtils.trim(keyAlgorithm);
            }
        }

        public String getKeySpecification() {
            return keySpecification;
        }

        public void setKeySpecification(String keySpecification) {
            this.keySpecification = StringUtils.trim(keySpecification);
        }

        public String getNewKeyAlias() {
            return newKeyAlias;
        }

        public void setNewKeyAlias(String newKeyAlias) {
            this.newKeyAlias = StringUtils.trim(newKeyAlias);
        }

        public boolean isSelectAlgFromList() {
            return selectAlgFromList;
        }

        public void setSelectAlgFromList(boolean selectAlgFromList) {
            this.selectAlgFromList = selectAlgFromList;
        }

        public boolean isSelectKeySpecFromList() {
            return selectKeySpecFromList;
        }

        public void setSelectKeySpecFromList(boolean selectKeyspecFromList) {
            this.selectKeySpecFromList = selectKeyspecFromList;
        }

        public List<SelectItem> getAlgorithmValues() {
            if (algMenuValues == null) {
                algMenuValues = KeyUtils.getAlgorithmsMap();
            }

            return algMenuValues;
        }

        public List<SelectItem> getKeySpecValues() {
            if (keySpecMenuValues == null) {
                keySpecMenuValues = KeyUtils.getKeySpecsMap(keyAlgorithm);
            }

            return keySpecMenuValues;
        }
    }

    public boolean isKeyGenerationDisabled() throws AdminNotAuthorizedException {
        return getWorkerSessionBean().isKeyGenerationDisabled();
    }

    /**
     * Set the error message on the workers where the duplicate key alias tried to use within the same crypto token.
     * Set the error message on the workers where CryptoToken is not set.
     *
     * Note: Finding any error and returning false causes to skip all the renew keys processes.
     *
     * @return False if any error found and return true otherwise
     */
    private boolean validateMultiKeyGeneration() throws AdminNotAuthorizedException {
        HashSet<String> aliasSet;
        HashMap<String, HashSet<String>> hashMap = new HashMap<>();
        String cryptoToken;
        String newKeyAlias;
        boolean result = true;

        for (RenewKeyWorker worker : getSelectedRenewKeyWorkers()) {
            cryptoToken = worker.getConfig().getProperty("CRYPTOTOKEN");
            newKeyAlias = worker.newKeyAlias;
            if (cryptoToken == null) {
                worker.setError("CryptoToken is not set");
                result = false;
            }
            if (hashMap.isEmpty() || !hashMap.containsKey(cryptoToken)) {
                aliasSet = new HashSet<>();
                aliasSet.add(newKeyAlias);
                hashMap.put(cryptoToken, aliasSet);
            } else {
                if (hashMap.get(cryptoToken).contains(newKeyAlias)) {
                    worker.setError("Duplicate Key Alias can not be set in a CryptoToken");
                    result = false;
                } else {
                    hashMap.get(cryptoToken).add(newKeyAlias);
                }
            }
        }
        return result;
    }
}
