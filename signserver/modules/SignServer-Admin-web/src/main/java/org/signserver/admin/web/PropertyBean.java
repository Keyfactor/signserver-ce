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

import jakarta.annotation.ManagedBean;
import jakarta.ejb.EJB;
import jakarta.enterprise.context.RequestScoped;
import jakarta.faces.annotation.ManagedProperty;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;

import java.io.Serializable;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@Named
@RequestScoped
public class PropertyBean implements Serializable {

    @EJB
    private AdminWebSessionBean workerSession;

    @Inject
    @ManagedProperty(value = "#{param.id}")
    private Integer id;

    @Inject
    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private String name;
    private String value;

    /**
     * Creates a new instance of PropertyBean
     */
    public PropertyBean() {
    }

    public AuthenticationBean getAuthBean() {
        return authBean;
    }

    public void setAuthBean(AuthenticationBean authBean) {
        this.authBean = authBean;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String submit() throws AdminNotAuthorizedException {
        // Set worker property
        workerSession.setWorkerProperty(authBean.getAdminCertificate(), id, name, value);
        workerSession.reloadConfiguration(authBean.getAdminCertificate(), id);

        // Continue to next page
        return "worker-configuration-added";
    }

}
