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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.ejb.EJBException;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.util.PropertiesApplier;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.InvalidWorkerIdException;

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
        } catch (AdminNotAuthorizedException | EJBException e) {
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
    protected void addAuthorizedClientGen2(int workerId, CertificateMatchingRule authClient) throws PropertiesApplierException {
        try {
            sessionBean.addAuthorizedClientGen2(adminCertificate, workerId, authClient);
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
    
    @Override
    protected void removeAuthorizedClientGen2(int workerId, CertificateMatchingRule authClient) throws PropertiesApplierException {
        try {
            sessionBean.removeAuthorizedClientGen2(adminCertificate, workerId, authClient);
        } catch (AdminNotAuthorizedException e) {
            throw new PropertiesApplierException(e);
        }
    }

    @Override
    protected void checkWorkerNamesAlreadyExists(List<String> workerNames, List<String> workerIds) throws PropertiesApplierException {
        boolean workerWithNameAlreadyExists = false;
        StringBuffer errorMessage = new StringBuffer();
        final List<String> alreadyExistingWorkerNames = new ArrayList<String>();
        errorMessage.append("Worker(s) with name already exists:");
        try {
            List existingWorkerNamesInDB = sessionBean.getAllWorkerNames(adminCertificate);
            for (int i = 0; i < workerNames.size(); i++) {
                final String workerName = workerNames.get(i);
                final String workerId = workerIds.get(i);
                if (existingWorkerNamesInDB.contains(workerName)) {
                    try {
                        final String workerIdInDB = String.valueOf(sessionBean.getWorkerIdByName(adminCertificate, workerName));

                        if (!workerIdInDB.equals(workerId)) {
                            alreadyExistingWorkerNames.add(workerName);
                            workerWithNameAlreadyExists = true;
                        }
                    } catch (InvalidWorkerIdException ex) {
                        /* this shouldn't happen, since we got the list of worker names
                         */
                    }
                }
            }

            // sort already found worker names to keep error message deterministic
            Collections.sort(alreadyExistingWorkerNames);

            alreadyExistingWorkerNames.forEach((name) -> {
                errorMessage.append(" ").append(name);
            });
            if (workerWithNameAlreadyExists) {
                throw new PropertiesApplierException(errorMessage.toString());
            }
        } catch (AdminNotAuthorizedException e) {
            throw new PropertiesApplierException(e);
        }
    }

}
