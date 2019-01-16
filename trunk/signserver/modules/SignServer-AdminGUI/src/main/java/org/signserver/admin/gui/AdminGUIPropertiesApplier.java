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
package org.signserver.admin.gui;

import java.util.List;
import javax.ejb.EJBException;
import javax.xml.ws.soap.SOAPFaultException;

import org.signserver.admin.gui.adminws.gen.AdminNotAuthorizedException_Exception;
import org.signserver.admin.gui.adminws.gen.IllegalRequestException_Exception;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.WorkerConfig;
import org.signserver.common.util.PropertiesApplier;

/**
 * Implementation of the properties applier using WS for the Admin GUI.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class AdminGUIPropertiesApplier extends PropertiesApplier {

    @Override
    protected void setGlobalProperty(String scope, String key, String value) throws PropertiesApplierException {
        try {
            SignServerAdminGUIApplication.getAdminWS().setGlobalProperty(scope, key, value);
        } catch (AdminNotAuthorizedException_Exception e) {
            throw new PropertiesApplierException(e);
        } catch (EJBException | SOAPFaultException ex) {
            throw new PropertiesApplierException("Operation failed on server side", ex);
        }
    }

    @Override
    protected void removeGlobalProperty(String scope, String key) throws PropertiesApplierException {
        try {
            SignServerAdminGUIApplication.getAdminWS().removeGlobalProperty(scope, key);
        } catch (AdminNotAuthorizedException_Exception e) {
            throw new PropertiesApplierException(e);
        } catch (EJBException | SOAPFaultException ex) {
            throw new PropertiesApplierException("Operation failed on server side", ex);
        }
    }

    @Override
    protected void setWorkerProperty(int workerId, String key, String value) throws PropertiesApplierException {
        try {
            SignServerAdminGUIApplication.getAdminWS().setWorkerProperty(workerId, key, value);
        } catch (AdminNotAuthorizedException_Exception e) {
            throw new PropertiesApplierException(e);
        } catch (EJBException | SOAPFaultException ex) {
            throw new PropertiesApplierException("Operation failed on server side", ex);
        }
    }

    @Override
    protected void removeWorkerProperty(int workerId, String key) throws PropertiesApplierException {
        try {
            SignServerAdminGUIApplication.getAdminWS().removeWorkerProperty(workerId, key);
        } catch (AdminNotAuthorizedException_Exception e) {
            throw new PropertiesApplierException(e);
        } catch (EJBException | SOAPFaultException ex) {
            throw new PropertiesApplierException("Operation failed on server side", ex);
        }
    }

    @Override
    protected void uploadSignerCertificate(int workerId, byte[] signerCert) throws PropertiesApplierException {
        try {
            SignServerAdminGUIApplication.getAdminWS().uploadSignerCertificate(workerId, signerCert, GlobalConfiguration.SCOPE_GLOBAL);
        } catch (AdminNotAuthorizedException_Exception e) {
            throw new PropertiesApplierException(e);
        } catch (IllegalRequestException_Exception ex) {
            throw new PropertiesApplierException("Illegal request", ex);
        } catch (EJBException | SOAPFaultException ex) {
            throw new PropertiesApplierException("Operation failed on server side", ex);
        }
    }

    @Override
    protected void uploadSignerCertificateChain(int workerId,
            List<byte[]> signerCertChain) throws PropertiesApplierException {
        try {
            SignServerAdminGUIApplication.getAdminWS().uploadSignerCertificateChain(workerId, signerCertChain, GlobalConfiguration.SCOPE_GLOBAL);
        } catch (AdminNotAuthorizedException_Exception e) {
            throw new PropertiesApplierException(e);
        } catch (IllegalRequestException_Exception ex) {
            throw new PropertiesApplierException("Illegal request", ex);
        } catch (EJBException | SOAPFaultException ex) {
            throw new PropertiesApplierException("Operation failed on server side", ex);
        }
    }

    @Override
    protected int genFreeWorkerId() throws PropertiesApplierException {
        try {
            final List<Integer> workerIds = SignServerAdminGUIApplication.getAdminWS().getWorkers(WorkerConfig.WORKERTYPE_ALL);
            int max = 0;
            
            for (final int workerId : workerIds) {
                if (workerId > max) {
                    max = workerId;
                }
            }
            
            return max + 1;
            
        } catch (AdminNotAuthorizedException_Exception e) {
            throw new PropertiesApplierException(e);
        }
            
    }

    @Override
    protected int getWorkerId(final String workerName) throws PropertiesApplierException {
        try {
            int workerId = SignServerAdminGUIApplication.getAdminWS().getWorkerId(workerName);
            
            if (workerId == 0) {
                throw new PropertiesApplierException("Unknown worker: " + workerName);
            }
            
            return workerId;
        } catch (AdminNotAuthorizedException_Exception e) {
            throw new PropertiesApplierException(e);
        }
    }

    @Override
    protected void addAuthorizedClient(int workerId, AuthorizedClient ac) throws PropertiesApplierException {
        try {
            final org.signserver.admin.gui.adminws.gen.AuthorizedClient authClient =
                    new org.signserver.admin.gui.adminws.gen.AuthorizedClient();
            
            authClient.setCertSN(ac.getCertSN());
            authClient.setIssuerDN(ac.getIssuerDN());
            SignServerAdminGUIApplication.getAdminWS().addAuthorizedClient(workerId, authClient);
        } catch (AdminNotAuthorizedException_Exception e) {
            throw new PropertiesApplierException(e);
        } catch (EJBException | SOAPFaultException ex) {
            throw new PropertiesApplierException("Operation failed on server side", ex);
        }
    }

    @Override
    protected void removeAuthorizedClient(int workerId, AuthorizedClient ac) throws PropertiesApplierException {
        try {
            final org.signserver.admin.gui.adminws.gen.AuthorizedClient authClient =
                    new org.signserver.admin.gui.adminws.gen.AuthorizedClient();
            
            authClient.setCertSN(ac.getCertSN());
            authClient.setIssuerDN(ac.getIssuerDN());
            SignServerAdminGUIApplication.getAdminWS().removeAuthorizedClient(workerId, authClient);
        } catch (AdminNotAuthorizedException_Exception e) {
            throw new PropertiesApplierException(e);
        } catch (EJBException | SOAPFaultException ex) {
            throw new PropertiesApplierException("Operation failed on server side", ex);
        }
    }

    @Override
    protected void workerNameAlreadyExists(List<String> workerNames) throws PropertiesApplierException {
        // TODO: Add findAllWorkerNames() logic in AdminWS for support in Admin GUI
    }

}
