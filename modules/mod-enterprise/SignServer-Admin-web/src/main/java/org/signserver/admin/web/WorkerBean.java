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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.xml.ws.soap.SOAPFaultException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.admin.web.ejb.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class WorkerBean {

    //@ManagedProperty(value = "#{param.id}")
    private Integer id;

    private String property;
    private String propertyValue;
    private String oldProperty;

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private Worker worker;
    private String status;
    private List<KeyValue<String, String>> config;
    private WorkerConfig workerConfig;

    private String destroyKeyAlias;
    private Integer destroyKeyStep = 0;
    private boolean destroyKeySuccess;
    private String destroyKeyError;

    /**
     * Creates a new instance of WorkerBean
     */
    public WorkerBean() {
    }

    public Worker getWorker() throws AdminNotAuthorizedException, NoSuchWorkerException {
        if (worker == null) {
            Properties conf = getWorkerConfig().getProperties();
            String name = conf.getProperty("NAME");
            if (name == null) {
                throw new NoSuchWorkerException(String.valueOf(id));
            }
            worker = new Worker(id, conf.containsKey("NAME"), name, conf);
        }
        return worker;
    }

    public AuthenticationBean getAuthBean() {
        return authBean;
    }

    public void setAuthBean(AuthenticationBean authBean) {
        this.authBean = authBean;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Integer getId() {
        return id;
    }

    @SuppressWarnings("UseSpecificCatch")
    public String getStatus() throws AdminNotAuthorizedException {
        if (status == null) {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            try {
                workerSessionBean.getStatus(authBean.getAdminCertificate(), new WorkerIdentifier(id)).displayStatus(new PrintStream(bout, false, StandardCharsets.UTF_8.toString()), true);
                status = bout.toString(StandardCharsets.UTF_8.toString());
            } catch (Throwable ignored) { // NOPMD: We safe-guard for bugs in worker implementations and don't want the GUI to fail for those.
                status = "Error getting status";
            }
        }
        return status;
    }

    public List<KeyValue<String, String>> getConfig() throws AdminNotAuthorizedException {
        if (config == null) {
            Properties properties = getWorkerConfig().getProperties();
            config = new ArrayList<>(properties.size());
            for (Map.Entry<Object, Object> entry : properties.entrySet()) {
                String value = (String) entry.getValue();
                if (value.length() > 50) {
                    value = value.substring(0, 50) + "...";
                }
                config.add(new KeyValue((String) entry.getKey(), value));
            }
            Collections.sort(config, new Comparator<KeyValue<String, String>>() {
                @Override
                public int compare(KeyValue<String, String> o1, KeyValue<String, String> o2) {
                    return o1.getKey().compareTo(o2.getKey());
                }
            });
        }

        return config;
    }

    private WorkerConfig getWorkerConfig() throws AdminNotAuthorizedException {
        if (workerConfig == null) {
            workerConfig = workerSessionBean.getCurrentWorkerConfig(authBean.getAdminCertificate(), id);
        }
        return workerConfig;
    }

    public String workerAction(String page) {
        StringBuilder sb = new StringBuilder();
        sb.append(page);
        sb.append("?faces-redirect=true&amp;includeViewParams=true");
        return sb.toString();
    }

    public String bulkAction(String page) {
        StringBuilder sb = new StringBuilder();
        sb.append(page);
        sb.append("?faces-redirect=true&amp;includeViewParams=true&amp;workers=").append(id).append("&amp;previous=worker");
        return sb.toString();
    }

    public String getDestroyKeyAlias() {
        return destroyKeyAlias;
    }

    public void setDestroyKeyAlias(String destroyKeyAlias) {
        this.destroyKeyAlias = destroyKeyAlias;
    }

    public void destroyKeyStep1Action() {
        destroyKeyStep = 1;
    }

    public void destroyKeyCancelAction() {
        destroyKeyStep = 0;
    }

    public void destroyKeyStep2Action() {
        destroyKeyStep = 2;
        destroyKeySuccess = false;
        try {
            destroyKeySuccess = workerSessionBean.removeKey(authBean.getAdminCertificate(), id, destroyKeyAlias);
            destroyKeyError = null;
        } catch (AdminNotAuthorizedException ex) {
            destroyKeyError = "Authorization denied:\n" + ex.getLocalizedMessage();
        } catch (CryptoTokenOfflineException ex) {
            destroyKeyError = "Unable to remove key because token was not active:\n" + ex.getLocalizedMessage();
        } catch (InvalidWorkerIdException | KeyStoreException | SignServerException | SOAPFaultException | EJBException ex) {
            destroyKeyError = "Unable to remove key:\n" + ex.getLocalizedMessage();
        }
    }

    public Integer getDestroyKeyStep() {
        return destroyKeyStep;
    }

    public void setDestroyKeyStep(Integer destroyKeyStep) {
        this.destroyKeyStep = destroyKeyStep;
    }

    public boolean isDestroyKeySuccess() {
        return destroyKeySuccess;
    }

    public String getDestroyKeyError() {
        return destroyKeyError;
    }

    public String getProperty() {
        return property;
    }

    public void setProperty(String property) {
        this.property = property;
    }

    public String getPropertyValue() throws AdminNotAuthorizedException {
        if (propertyValue == null && property != null) {
            propertyValue = getWorkerConfig().getProperty(property);
        }
        return propertyValue;
    }

    public void setPropertyValue(String propertyValue) {
        this.propertyValue = propertyValue;
    }

    public String getOldProperty() {
        if (oldProperty == null) {
            oldProperty = property;
        }
        return oldProperty;
    }

    public void setOldProperty(String oldProperty) {
        this.oldProperty = oldProperty;
    }

    public String editPropertyAction() throws AdminNotAuthorizedException {
        String oldPropertyName = getOldProperty();

        if (!oldPropertyName.equals(property)) {
            workerSessionBean.removeWorkerProperty(getAuthBean().getAdminCertificate(), id, oldPropertyName);
        }
        workerSessionBean.setWorkerProperty(getAuthBean().getAdminCertificate(), id, property, propertyValue);
        workerSessionBean.reloadConfiguration(getAuthBean().getAdminCertificate(), id);
        return "worker-configuration?faces-redirect=true&amp;includeViewParams=true&amp;id=" + id;
    }

    public String addPropertyAction() throws AdminNotAuthorizedException {
        workerSessionBean.setWorkerProperty(getAuthBean().getAdminCertificate(), id, property, propertyValue);
        workerSessionBean.reloadConfiguration(getAuthBean().getAdminCertificate(), id);
        return "worker-configuration?faces-redirect=true&amp;includeViewParams=true&amp;id=" + id;
    }

    public String removePropertyAction() throws AdminNotAuthorizedException {
        workerSessionBean.removeWorkerProperty(getAuthBean().getAdminCertificate(), id, property);
        workerSessionBean.reloadConfiguration(getAuthBean().getAdminCertificate(), id);
        return "worker-configuration?faces-redirect=true&amp;includeViewParams=true&amp;id=" + id;
    }

    public boolean isHasCrypto() throws AdminNotAuthorizedException {
        Properties properties = getWorkerConfig().getProperties();
        return properties.containsKey(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS);
    }

}
