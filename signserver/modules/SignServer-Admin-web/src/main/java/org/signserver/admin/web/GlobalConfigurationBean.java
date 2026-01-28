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

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import static java.net.URLEncoder.encode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;

import jakarta.ejb.EJB;
import jakarta.faces.annotation.ManagedProperty;
import jakarta.faces.view.ViewScoped;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import org.apache.log4j.Logger;
import org.signserver.common.CompileTimeSettings;
import org.signserver.common.GlobalConfiguration;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.auth.LoginBean;
import org.signserver.admin.web.ejb.AdminWebSessionBean;
import org.signserver.common.IllegalRequestException;

/**
 * @author Markus Kilås
 * @version $Id$
 */
@Named
@ViewScoped
public class GlobalConfigurationBean implements Serializable {
    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(GlobalConfigurationBean.class);

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @Inject
    private LoginBean loginBean;

    @Inject
    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private List<Entry<Object, Object>> config;
    private Map<Object, Boolean> selectedProperties;
    private List<String> toDelete;

    private String oldProperty;
    private String property;
    private String propertyValue;

    private final Boolean isAdminAllowedEnabled = CompileTimeSettings.getInstance().getAdminAllowAnyEnabled();

    /**
     * Creates a new instance of GlobalConfigurationBean.
     */
    public GlobalConfigurationBean() {
    }

    public AuthenticationBean getAuthBean() {
        return authBean;
    }

    public void setAuthBean(AuthenticationBean authBean) {
        this.authBean = authBean;
    }

    public List<Entry<Object, Object>> getConfig() throws AdminNotAuthorizedException {
        if (config == null) {
            GlobalConfiguration globalConfiguration = workerSessionBean.getGlobalConfiguration(loginBean.getAdminPrincipal());
            config = new ArrayList<>(globalConfiguration.getConfig().entrySet());
            Collections.sort(config, new Comparator<Entry<Object, Object>>() {
                @Override
                public int compare(Entry<Object, Object> o1, Entry<Object, Object> o2) {
                    return String.valueOf(o1).compareTo(String.valueOf(o2));
                }
            });
        }
        return config;
    }

    public Map<Object, Boolean> getSelectedProperties() {
        if (selectedProperties == null) {
            selectedProperties = new HashMap<>();
        }
        return selectedProperties;
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

    public String getProperty() {
        return property;
    }

    public void setProperty(String property) {
        this.property = property;
    }

    public String getPropertyValue() throws AdminNotAuthorizedException {
        if (propertyValue == null) {
            GlobalConfiguration globalConfiguration = workerSessionBean.getGlobalConfiguration(loginBean.getAdminPrincipal());
            propertyValue = globalConfiguration.getProperty(property, "");
        }
        return propertyValue;
    }

    public void setPropertyValue(String propertyValue) {
        this.propertyValue = propertyValue;
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

    public String editPropertyAction() throws AdminNotAuthorizedException, IllegalRequestException {
        String oldPropertyName = getOldProperty();
        // Remove scope part
        String key;
        if (property.contains(".")) {
            key = property.substring(
                    property.indexOf(".") + 1).toUpperCase(Locale.ENGLISH);
        } else {
            key = property.toUpperCase(Locale.ENGLISH);
        }
        // If Allow any is the property to change and admin.allowany.enabled is false
        if (key.equals("ALLOWANYWSADMIN") && !isAdminAllowedEnabled) {
            // Changing to false is always allowed.
            if (propertyValue.equalsIgnoreCase("false")) {
                performEdit(oldPropertyName, key);
            } else {
                // Changing to anything but false is not allowed
                throw new IllegalRequestException("Allow any is disabled and can not be enabled after deployment.");
            }

        } else {
            performEdit(oldPropertyName, key);
        }
        return "global-configuration?faces-redirect=true";
    }

    public String removePropertyAction() throws AdminNotAuthorizedException, IllegalRequestException {
        for (String prop : getToDelete()) {
            // Remove scope part
            if (prop.contains(".")) {
                prop = prop.substring(prop.indexOf(".") + 1);
            }
            if (!prop.equals("ALLOWANYWSADMIN") || isAdminAllowedEnabled) {
                workerSessionBean.removeGlobalProperty(loginBean.getAdminPrincipal(), GlobalConfiguration.SCOPE_GLOBAL, prop);
            } else {
                throw new IllegalRequestException("Allow any is disabled can't be removed after deployment.");
            }
        }
        return "global-configuration?faces-redirect=true";
    }

    public String addPropertyAction() throws AdminNotAuthorizedException, IllegalRequestException {
        // Remove scope part
        String oldKey;
        if (property.contains(".")) {
            oldKey = property.substring(
                    property.indexOf(".") + 1);
        } else {
            oldKey = property;
        }

        // Remove illegal characters
        oldKey = oldKey.replaceAll(",", "").replaceAll("%", "");
        if (oldKey.equals("ALLOWANYWSADMIN") && !isAdminAllowedEnabled) {
            throw new IllegalRequestException("Allow any is disabled and can not be added after deployment.");
        }
        workerSessionBean.setGlobalProperty(loginBean.getAdminPrincipal(), GlobalConfiguration.SCOPE_GLOBAL, oldKey, propertyValue);
        return "global-configuration?faces-redirect=true";
    }

    public String bulkAction(String page) throws UnsupportedEncodingException {
        StringBuilder sb = new StringBuilder();
        sb.append(page);
        sb.append("?faces-redirect=true&amp;includeViewParams=true&amp;property=");
        for (Map.Entry<Object, Boolean> entry : getSelectedProperties().entrySet()) {
            if (entry.getValue()) {
                sb.append(encode(entry.getKey().toString(), "UTF-8")).append(",");
            }
        }
        return sb.toString();
    }

    /**
     * Reload global configuration from database.
     * config must be null to force the getConfig() reload from database.
     */
    public String reloadFromDatabase() throws AdminNotAuthorizedException {
        // invalidate old cached config
        config = null;
        config = getConfig();
        return "global-configuration?faces-redirect=true;";
    }


    /**
     * A method that performs the edit of a global configuration property.
     * @param oldPropertyName
     * @param key
     * @return A redirect in the GUI when the edit has been performed
     * @throws AdminNotAuthorizedException
     */
    private void performEdit(String oldPropertyName, String key) throws AdminNotAuthorizedException, IllegalRequestException {
        if (!oldPropertyName.equals(property)) {
            // Remove scope part
            String oldKey;
            if (oldPropertyName.contains(".")) {
                oldKey = oldPropertyName.substring(
                        oldPropertyName.indexOf(".") + 1);
            } else {
                oldKey = oldPropertyName;
            }
            workerSessionBean.removeGlobalProperty(loginBean.getAdminPrincipal(), GlobalConfiguration.SCOPE_GLOBAL, oldKey);
        }

        // Remove illegal characters
        key = key.replaceAll(",", "").replaceAll("%", "");

        workerSessionBean.setGlobalProperty(loginBean.getAdminPrincipal(), GlobalConfiguration.SCOPE_GLOBAL, key, propertyValue);
    }
}
