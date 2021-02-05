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
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.ResourceBundle;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.xml.ws.soap.SOAPFaultException;
import org.apache.commons.lang.StringUtils;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;
import org.signserver.common.WorkerType;

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
    private String propertyValueSecret;
    private String propertyValueConfirmation;
    private String propertyValueConfirmationError;
    
    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    @ManagedProperty("#{text}")
    private ResourceBundle text;
    
    private Worker worker;
    private String status;
    private List<KeyValue<String, String>> config;
    private Map<String, Boolean> selectedProperties;
    private List<String> toDelete;
    // keep a separate instance of the properties as the API so far has
    // a separate method for the retrieving the properties with masked values
    private Properties workerProperties;
    private WorkerConfig workerConfig;

    private String destroyKeyAlias;
    private Integer destroyKeyStep = 0;
    private boolean destroyKeySuccess;
    private String destroyKeyError;
    
    // string to use to represent masked value when presenting worker properties
    // list and status properties
    private static final String MASKED_VALUE = "\u25cf\u25cf\u25cf\u25cf\u25cf\u25cf";

    /**
     * Creates a new instance of WorkerBean
     */
    public WorkerBean() {
    }

    public Worker getWorker() throws AdminNotAuthorizedException {
        if (worker == null) {
            Properties conf = getWorkerProperties();
            boolean existing;
            String name = conf.getProperty("NAME");
            if (name == null) {
                name = "Unknown ID " + getId();
                existing = false;
            } else {
                existing = true;
            }
            
            worker = new Worker(getId(), existing, name, conf);
        }
        return worker;
    }

    public Map<String, Boolean> getSelectedProperties() {
        if (selectedProperties == null) {
            selectedProperties = new HashMap<>();
        }
        return selectedProperties;
    }

    public AuthenticationBean getAuthBean() {
        return authBean;
    }

    public void setAuthBean(AuthenticationBean authBean) {
        this.authBean = authBean;
    }
    
    public void setText(ResourceBundle text) {
        this.text = text;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Integer getId() {
        if (id == null) {
            id = 0;
        }
        return id;
    }

    @SuppressWarnings("UseSpecificCatch")
    public String getStatus() throws AdminNotAuthorizedException {
        if (status == null) {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            try {
                workerSessionBean.getStatus(authBean.getAdminCertificate(), new WorkerIdentifier(id)).displayStatus(new PrintStream(bout, false, StandardCharsets.UTF_8.toString()), true);
                status = bout.toString(StandardCharsets.UTF_8.toString());
                status = status.replaceAll(WorkerConfig.WORKER_PROPERTY_MASK_PLACEHOLDER,
                                           MASKED_VALUE);
            } catch (Throwable ignored) { // NOPMD: We safe-guard for bugs in worker implementations and don't want the GUI to fail for those.
                status = "Error getting status";
            }
        }
        return status;
    }

    public List<KeyValue<String, String>> getConfig() throws AdminNotAuthorizedException {
        if (config == null) {
            Properties properties = getWorkerProperties();
            config = new ArrayList<>(properties.size());
            for (Map.Entry<Object, Object> entry : properties.entrySet()) {
                String value = (String) entry.getValue();
                if (value.length() > 50) {
                    value = value.substring(0, 50) + "...";
                } else if (WorkerConfig.WORKER_PROPERTY_MASK_PLACEHOLDER.equals(value)) {
                    value = MASKED_VALUE;
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

    private Properties getWorkerProperties() throws AdminNotAuthorizedException {
        if (workerProperties == null) {
            workerProperties = workerSessionBean.getProperties(authBean.getAdminCertificate(), getId());
        }
        return workerProperties;
    }

    private WorkerConfig getWorkerConfig() throws AdminNotAuthorizedException {
        if (workerConfig == null) {
            workerConfig = workerSessionBean.getCurrentWorkerConfig(authBean.getAdminCertificate(), getId());
        }
        return workerConfig;
    }
    
    public boolean getShouldMaskProperty()
        throws AdminNotAuthorizedException {
        return getWorkerConfig().shouldMaskProperty(property);
    }
    
    public List<String> getToDelete() {
        if (toDelete == null) {
            toDelete = new ArrayList<>();
            if (property != null) {
                String[] properties = property.split(",");
                toDelete.addAll(Arrays.asList(properties));
            }
            Collections.sort(toDelete);
        }
        return toDelete;
    }

    public String workerAction(String page) {
        StringBuilder sb = new StringBuilder();
        sb.append(page);
        sb.append("?faces-redirect=true&amp;includeViewParams=true");
        return sb.toString();
    }

    public String bulkAction(String page) {
        return bulkAction(page, "worker");
    }
    
    public String bulkAction(String page, String previous) {
        StringBuilder sb = new StringBuilder();
        sb.append(StringUtils.trim(page));
        sb.append("?faces-redirect=true&amp;includeViewParams=true&amp;workers=").append(getId()).append("&amp;previous=").append(previous);
        return sb.toString();
    }

    public String bulkActionProperties(String page) {
        StringBuilder sb = new StringBuilder();
        sb.append(StringUtils.trim(page));
        sb.append("?faces-redirect=true&amp;includeViewParams=true&amp;property=");
        for (Map.Entry<String, Boolean> entry : getSelectedProperties().entrySet()) {
            if (entry.getValue()) {
                sb.append(entry.getKey()).append(",");
            }
        }
        return sb.toString();
    }

    public String getDestroyKeyAlias() {
        return destroyKeyAlias;
    }

    public void setDestroyKeyAlias(String destroyKeyAlias) {
        this.destroyKeyAlias = StringUtils.trim(destroyKeyAlias);
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
            destroyKeySuccess = workerSessionBean.removeKey(authBean.getAdminCertificate(), getId(), destroyKeyAlias);
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
            propertyValue = getWorkerProperties().getProperty(property);
        }
        return propertyValue;
    }

    public void setPropertyValue(String propertyValue) {
        this.propertyValue = propertyValue;
    }
    
    public String getPropertyValueSecret() {
        return propertyValueSecret;
    }
    
    public void setPropertyValueSecret(String propertyValueSecret) {
        this.propertyValueSecret = propertyValueSecret;
    }
    
    public String getPropertyValueConfirmation() {
        return propertyValueConfirmation; 
    }
    
    public void setPropertyValueConfirmation(String propertyValueConfirmation) {
        this.propertyValueConfirmation = propertyValueConfirmation;
    }
    
    public String getPropertyValueConfirmationError() {
        return propertyValueConfirmationError;
    }
    
    public void setPropertyValueConfirmationError(String propertyValueConfirmationError) {
        this.propertyValueConfirmationError = propertyValueConfirmationError;
    }

    public String getOldProperty() {
        if (oldProperty == null) {
            oldProperty = property;
        }
        return oldProperty;
    }

    public void setOldProperty(String oldProperty) {
        this.oldProperty = StringUtils.trim(oldProperty);
    }

    public String editPropertyAction() throws AdminNotAuthorizedException {
        String oldPropertyName = getOldProperty();
        String key = property;
        final String oldValue = workerConfig.getProperty(oldPropertyName);

        if (!oldPropertyName.equals(key)) {
            workerSessionBean.removeWorkerProperty(getAuthBean().getAdminCertificate(), getId(), oldPropertyName);
        }
        
        // Remove illegal characters
        key = key.replaceAll(",", "").replaceAll("%", "");

        // if the property is a masked one, check the "password" entry and
        // confirmed entry, and ensure they are equal
        if (workerConfig.shouldMaskProperty(oldPropertyName)) {
            // if the user left the secret entry unchanged and didn't fill in
            // a confirmation value, just save the old value, this allows
            // renaming properties (i.e. commenting out) without entering the
            // value again
            if (propertyValueSecret.isEmpty() && propertyValueConfirmation.isEmpty()) {
                workerSessionBean.setWorkerProperty(getAuthBean().getAdminCertificate(),
                                                    getId(), key, oldValue);
            } else if (!propertyValueConfirmation.equals(propertyValueSecret)) {
                propertyValueConfirmationError = text.getString("The_values_do_not_match");
                return null;
            } else {
                workerSessionBean.setWorkerProperty(getAuthBean().getAdminCertificate(), getId(), key, propertyValueSecret);
            }
        } else {
            workerSessionBean.setWorkerProperty(getAuthBean().getAdminCertificate(), getId(), key, propertyValue);
        }
        workerSessionBean.reloadConfiguration(getAuthBean().getAdminCertificate(), getId());
        return "worker-configuration?faces-redirect=true&amp;includeViewParams=true&amp;id=" + getId();
    }

    public String addPropertyAction() throws AdminNotAuthorizedException {
        String key = property;

        // Remove illegal characters
        key = key.replaceAll(",", "").replaceAll("%", "");

        workerSessionBean.setWorkerProperty(getAuthBean().getAdminCertificate(), getId(), key, propertyValue);
        workerSessionBean.reloadConfiguration(getAuthBean().getAdminCertificate(), getId());
        return "worker-configuration?faces-redirect=true&amp;includeViewParams=true&amp;id=" + getId();
    }

    public String removePropertyAction() throws AdminNotAuthorizedException {
        for (String prop : getToDelete()) {
            workerSessionBean.removeWorkerProperty(getAuthBean().getAdminCertificate(), getId(), prop);
            workerSessionBean.reloadConfiguration(getAuthBean().getAdminCertificate(), getId());
        }
        return "worker-configuration?faces-redirect=true&amp;includeViewParams=true&amp;id=" + getId();
    }

    public boolean isHasCrypto() throws AdminNotAuthorizedException {
        Properties properties = getWorkerProperties();
        boolean isCryptoWorker = WorkerType.CRYPTO_WORKER.name().equals(properties.get(WorkerConfig.TYPE));
        return properties.containsKey(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS) || isCryptoWorker;
    }
    
    public boolean isKeyGenerationDisabled() throws AdminNotAuthorizedException {
        return workerSessionBean.isKeyGenerationDisabled();
    }
}
