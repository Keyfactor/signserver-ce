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

import java.security.cert.X509Certificate;
import java.util.List;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.util.PropertiesApplier;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;

/**
 * Implementation of the properties applier using WS for the Admin GUI.
 *
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class AdminWebPropertiesApplier extends PropertiesApplier {

    private final AdminWebSessionBean sessionBean;
    private final X509Certificate adminCertificate;

    public AdminWebPropertiesApplier(AdminWebSessionBean sessionBean, X509Certificate adminCertificate) {
        this.sessionBean = sessionBean;
        this.adminCertificate = adminCertificate;
    }

    @Override
    protected void setGlobalProperty(String scope, String key, String value) throws PropertiesApplierException {
        try {
            sessionBean.setGlobalProperty(adminCertificate, scope, key, value);
        } catch (AdminNotAuthorizedException e) {
            throw new PropertiesApplierException(e);
        }
    }

    @Override
    protected void removeGlobalProperty(String scope, String key) throws PropertiesApplierException {
        try {
            sessionBean.removeGlobalProperty(adminCertificate, scope, key);
        } catch (AdminNotAuthorizedException e) {
            throw new PropertiesApplierException(e);
        }
    }

    @Override
    protected void setWorkerProperty(int workerId, String key, String value) throws PropertiesApplierException {
        try {
            sessionBean.setWorkerProperty(adminCertificate, workerId, key, value);
        } catch (AdminNotAuthorizedException e) {
            throw new PropertiesApplierException(e);
        }
    }

    @Override
    protected void removeWorkerProperty(int workerId, String key) throws PropertiesApplierException {
        try {
            sessionBean.removeWorkerProperty(adminCertificate, workerId, key);
        } catch (AdminNotAuthorizedException e) {
            throw new PropertiesApplierException(e);
        }
    }

    @Override
    protected void uploadSignerCertificate(int workerId, byte[] signerCert) throws PropertiesApplierException {
        try {
            sessionBean.uploadSignerCertificate(adminCertificate, workerId, signerCert, GlobalConfiguration.SCOPE_GLOBAL);
        } catch (AdminNotAuthorizedException e) {
            throw new PropertiesApplierException(e);
        } catch (IllegalRequestException ex) {
            throw new PropertiesApplierException("Illegal request", ex);
        }
    }

    @Override
    protected void uploadSignerCertificateChain(int workerId,
            List<byte[]> signerCertChain) throws PropertiesApplierException {
        try {
            sessionBean.uploadSignerCertificateChain(adminCertificate, workerId, signerCertChain, GlobalConfiguration.SCOPE_GLOBAL);
        } catch (AdminNotAuthorizedException e) {
            throw new PropertiesApplierException(e);
        } catch (IllegalRequestException ex) {
            throw new PropertiesApplierException("Illegal request", ex);
        }
    }

    @Override
    protected int genFreeWorkerId() throws PropertiesApplierException {
        try {
            final List<Integer> workerIds = sessionBean.getAllWorkers(adminCertificate);
            int max = 0;

            for (final int workerId : workerIds) {
                if (workerId > max) {
                    max = workerId;
                }
            }

            return max + 1;

        } catch (AdminNotAuthorizedException e) {
            throw new PropertiesApplierException(e);
        }

    }

    @Override
    protected int getWorkerId(final String workerName) throws PropertiesApplierException {
        try {
            int workerId = sessionBean.getWorkerId(adminCertificate, workerName);

            if (workerId == 0) {
                throw new PropertiesApplierException("Unknown worker: " + workerName);
            }

            return workerId;
        } catch (AdminNotAuthorizedException e) {
            throw new PropertiesApplierException(e);
        }
    }

    @Override
    protected void addAuthorizedClient(int workerId, AuthorizedClient authClient) throws PropertiesApplierException {
        try {
            sessionBean.addAuthorizedClient(adminCertificate, workerId, authClient);
        } catch (AdminNotAuthorizedException e) {
            throw new PropertiesApplierException(e);
        }
    }

    @Override
    protected void removeAuthorizedClient(int workerId, AuthorizedClient authClient) throws PropertiesApplierException {
        try {
            sessionBean.removeAuthorizedClient(adminCertificate, workerId, authClient);
        } catch (AdminNotAuthorizedException e) {
            throw new PropertiesApplierException(e);
        }
    }

}
