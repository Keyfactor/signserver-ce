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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import org.apache.commons.lang.StringUtils;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericPropertiesRequest;
import org.signserver.common.GenericPropertiesResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.RequestAndResponseManager;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.module.renewal.common.RenewalWorkerProperties;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RenewSignerBulkBean extends BulkBean {

    private List<MyWorker> myWorkers;

    /**
     * Creates a new instance of WorkersManagedBean
     */
    public RenewSignerBulkBean() {

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

                MyWorker worker = new MyWorker(id, exists, name, config.getProperties(), config.getProperty(RenewalWorkerProperties.WORKERPROPERTY_RENEWWORKER));

                updateStatus(worker);
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

    public String renewSignerAction() throws AdminNotAuthorizedException {
        //FacesMessage errorMessage = new FacesMessage("Test error");
        //errorMessage.setSeverity(FacesMessage.SEVERITY_ERROR);
        //FacesContext.getCurrentInstance().addMessage(null, errorMessage);

        for (MyWorker worker : getMySelectedWorkers()) {
            try {
                final Properties requestProperties = new Properties();
                requestProperties.setProperty(
                        RenewalWorkerProperties.REQUEST_WORKER,
                        worker.getName());
                /*requestProperties.setProperty(
                            RenewalWorkerProperties.REQUEST_AUTHCODE,
                            String.valueOf(authCode));*/
                final GenericPropertiesRequest request
                        = new GenericPropertiesRequest(requestProperties);

                final Collection<byte[]> responses
                        = getWorkerSessionBean().process(getAuthBean().getAdminCertificate(), worker.getRenewalWorker(),
                                Collections.singletonList(RequestAndResponseManager.serializeProcessRequest(request)));

                final Properties responseProperties;

                if (responses.size() > 0) {
                    final GenericPropertiesResponse response
                            = (GenericPropertiesResponse) RequestAndResponseManager.parseProcessResponse(
                                    responses.iterator().next());
                    responseProperties = response.getProperties();

                    if (RenewalWorkerProperties.RESPONSE_RESULT_OK.equals(
                            responseProperties.getProperty(
                                    RenewalWorkerProperties.RESPONSE_RESULT))) {

                        getSelectedIds().put(worker.getId(), Boolean.FALSE);
                        worker.setSuccess("OK");
                        worker.setError(null);
                    } else {
                        worker.setSuccess(null);
                        worker.setError(responseProperties.getProperty(RenewalWorkerProperties.RESPONSE_MESSAGE));
                    }
                } else {
                    worker.setSuccess(null);
                    worker.setError("Got empty response");
                }
            } catch (InvalidWorkerIdException | IllegalRequestException | CryptoTokenOfflineException | SignServerException | IOException ex) {
                worker.setSuccess(null);
                worker.setError("Renewal failed: " + ex.getMessage());
            }

            // Note: update the status
            updateStatus(worker);
        }

        if (getSelectedIds().isEmpty()) {
            return "workers?faces-redirect=true&amp;includeViewParams=true&amp;" + "selected=" + StringUtils.join(getWorkerIdsList(), ",");
        } else {
            return "";
        }
    }

    private void updateStatus(MyWorker worker) throws AdminNotAuthorizedException {
        String notAfter = "n/a";
        try {
            Date signingValidityNotAfter = getWorkerSessionBean().getSigningValidityNotAfter(getAuthBean().getAdminCertificate(), worker.getId());
            if (signingValidityNotAfter != null) {
                notAfter = signingValidityNotAfter.toString(); // TODO format
            }
        } catch (CryptoTokenOfflineException ignored) { // NOPMD
        }
        worker.setNotAfter(notAfter);

        final StringBuilder signings = new StringBuilder();
        try {
            final String keyUsageLimit = worker.getConfig().getProperty("KEYUSAGELIMIT");
            signings.append(String.valueOf(getWorkerSessionBean().getKeyUsageCounterValue(getAuthBean().getAdminCertificate(), worker.getId())));
            if (keyUsageLimit != null && !"-1".equals(keyUsageLimit)) {
                signings.append(" of ").append(keyUsageLimit);
            }
        } catch (CryptoTokenOfflineException ignored) { // NOPMD
        }
        worker.setSignings(signings.toString());
    }

    public static class MyWorker extends Worker {

        private String notAfter;
        private String signings;
        private String renewalWorker;

        public MyWorker(int id, boolean exists, String name, Properties config, String renewalWorker) {
            super(id, exists, name, config);
            this.renewalWorker = renewalWorker;
        }

        public String getNotAfter() {
            return notAfter;
        }

        public void setNotAfter(String notAfter) {
            this.notAfter = notAfter;
        }

        public String getSignings() {
            return signings;
        }

        public void setSignings(String signings) {
            this.signings = StringUtils.trim(signings);
        }

        public String getRenewalWorker() {
            return renewalWorker;
        }

        public void setRenewalWorker(String renewalWorker) {
            this.renewalWorker = StringUtils.trim(renewalWorker);
        }

    }
}
