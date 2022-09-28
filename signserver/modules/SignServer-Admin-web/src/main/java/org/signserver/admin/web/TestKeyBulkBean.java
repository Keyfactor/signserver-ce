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

import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import org.apache.commons.lang.StringUtils;
import javax.ejb.EJBException;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.WorkerConfig;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class TestKeyBulkBean extends BulkBean {

    private List<TestKeyWorker> myWorkers;

    private List<String> keysList;
    private String keys;

    /**
     * Creates a new instance of WorkersManagedBean
     */
    public TestKeyBulkBean() {

    }

    public List<TestKeyWorker> getTestKeyWorkers() throws AdminNotAuthorizedException {
        if (myWorkers == null) {
            myWorkers = new ArrayList<>();
            Iterator<String> ks = getKeysList().iterator();

            for (int id : getWorkerIdsList()) {
                WorkerConfig config = getWorkerSessionBean().getCurrentWorkerConfig(getAuthBean().getAdminCertificate(), id);
                String name = config.getProperty("NAME");
                boolean exists = true;
                if (name == null) {
                    name = "Not Found";
                    exists = false;
                }

                String alias = ks.hasNext() ? ks.next() : null;
                final boolean fixedAlias;

                if (alias == null || alias.isEmpty()) {
                    alias = config.getProperty("NEXTCERTSIGNKEY");
                    fixedAlias = false;
                } else {
                    fixedAlias = true;
                }

                if (alias == null) {
                    alias = config.getProperty("DEFAULTKEY");
                }
                if (alias == null) {
                    alias = "all";
                }

                myWorkers.add(new TestKeyWorker(id, exists, name, config.getProperties(), alias, fixedAlias));

                // Select checkbox
                getSelectedIds().put(id, exists);
            }
        }
        return myWorkers;
    }

    public List<TestKeyWorker> getSelectedTestKeyWorkers() throws AdminNotAuthorizedException {
        final ArrayList<TestKeyWorker> results = new ArrayList<>(getSelectedIds().size());
        for (TestKeyWorker worker : getTestKeyWorkers()) {
            if (Boolean.TRUE.equals(getSelectedIds().get(worker.getId()))) {
                results.add(worker);
            }
        }
        return results;
    }

    public String getKeys() {
        return keys;
    }

    public void setKeys(String keys) {
        this.keys = StringUtils.trim(keys);
    }

    public List<String> getKeysList() {
        if (keysList == null) {
            keysList = new ArrayList<>();
            if (keys != null) {
                String[] split = keys.split(",");
                keysList = Arrays.asList(split);
            }
        }
        return keysList;
    }

    public void testKeyAction() throws AdminNotAuthorizedException {
        //FacesMessage errorMessage = new FacesMessage("Test error");
        //errorMessage.setSeverity(FacesMessage.SEVERITY_ERROR);
        //FacesContext.getCurrentInstance().addMessage(null, errorMessage);

        for (TestKeyWorker worker : getSelectedTestKeyWorkers()) {
            try {
                // Test the key
                final Collection<KeyTestResult> result
                        = getWorkerSessionBean().testKey(getAuthBean().getAdminCertificate(), worker.getId(), worker.getAlias(), "");

                if (result.isEmpty()) {
                    worker.setError("(No key found, token offline?)");
                    worker.setSuccess(null);
                } else {
                    final StringBuilder sbSuccess = new StringBuilder();
                    final StringBuilder sbError = new StringBuilder();
                    for (KeyTestResult key : result) {
                        if (key.isSuccess()) {
                            sbSuccess.append("  ");
                            sbSuccess.append(key.getAlias());
                            sbSuccess.append(", ");
                            sbSuccess.append("SUCCESS");
                            sbSuccess.append(", ");
                            sbSuccess.append(key.getPublicKeyHash());
                            sbSuccess.append(", ");
                            sbSuccess.append(key.getStatus());
                            sbSuccess.append("\n");
                        } else {
                            sbError.append("  ");
                            sbError.append(key.getAlias());
                            sbError.append(", ");
                            sbError.append("FAILURE");
                            sbError.append(", ");
                            sbError.append(key.getPublicKeyHash());
                            sbError.append(", ");
                            sbError.append(key.getStatus());
                            sbError.append("\n");
                        }
                    }
                    worker.setSuccess(sbSuccess.toString());
                    worker.setError(sbError.toString());
                    
                    if (!worker.isFixedAlias()) {
                        getSelectedIds().remove(worker.getId());
                    }
                }

            } catch (CryptoTokenOfflineException | InvalidWorkerIdException | KeyStoreException | EJBException ex) {
                worker.setError("Failed: " + ex.getMessage());
                worker.setSuccess(null);
            }
        }
    }

    public static class TestKeyWorker extends Worker {

        private String alias;
        private final boolean fixedAlias;

        public TestKeyWorker(int id, boolean exists, String name, Properties config, String alias, boolean fixedAlias) {
            super(id, exists, name, config);
            this.alias = alias;
            this.fixedAlias = fixedAlias;
        }

        public String getAlias() {
            return alias;
        }

        public void setAlias(String alias) {
            this.alias = StringUtils.trim(alias);
        }

        public boolean isFixedAlias() {
            return fixedAlias;
        }
    }
}
