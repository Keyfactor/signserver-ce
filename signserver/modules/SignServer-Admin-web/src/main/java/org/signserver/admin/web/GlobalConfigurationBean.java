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

import java.io.UnsupportedEncodingException;
import static java.net.URLEncoder.encode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;

/**
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class GlobalConfigurationBean {
    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(GlobalConfigurationBean.class);

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private List<Entry<Object, Object>> config;
    private Map<Object, Boolean> selectedProperties;
    private List<String> toDelete;

    private String oldProperty;
    private String property;
    private String propertyValue;

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
            GlobalConfiguration globalConfiguration = workerSessionBean.getGlobalConfiguration(authBean.getAdminCertificate());
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
            GlobalConfiguration globalConfiguration = workerSessionBean.getGlobalConfiguration(authBean.getAdminCertificate());
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

    public String editPropertyAction() throws AdminNotAuthorizedException {
        String oldPropertyName = getOldProperty();

        // Remove scope part
        String key;
        if (property.contains(".")) {
            key = property.substring(
                    property.indexOf(".") + 1);
        } else {
            key = property;
        }

        if (!oldPropertyName.equals(property)) {
            // Remove scope part
            String oldKey;
            if (oldPropertyName.contains(".")) {
                oldKey = oldPropertyName.substring(
                        oldPropertyName.indexOf(".") + 1);
            } else {
                oldKey = oldPropertyName;
            }

            workerSessionBean.removeGlobalProperty(getAuthBean().getAdminCertificate(), GlobalConfiguration.SCOPE_GLOBAL, oldKey);
        }

        // Remove illegal characters
        key = key.replaceAll(",", "").replaceAll("%", "");

        workerSessionBean.setGlobalProperty(getAuthBean().getAdminCertificate(), GlobalConfiguration.SCOPE_GLOBAL, key, propertyValue);
        return "global-configuration?faces-redirect=true";
    }

    public String removePropertyAction() throws AdminNotAuthorizedException {
        for (String prop : getToDelete()) {
            // Remove scope part
            if (prop.contains(".")) {
                prop = prop.substring(prop.indexOf(".") + 1);
            }
            workerSessionBean.removeGlobalProperty(getAuthBean().getAdminCertificate(), GlobalConfiguration.SCOPE_GLOBAL, prop);
        }
        return "global-configuration?faces-redirect=true";
    }

    public String addPropertyAction() throws AdminNotAuthorizedException {
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

        workerSessionBean.setGlobalProperty(getAuthBean().getAdminCertificate(), GlobalConfiguration.SCOPE_GLOBAL, oldKey, propertyValue);
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
}
