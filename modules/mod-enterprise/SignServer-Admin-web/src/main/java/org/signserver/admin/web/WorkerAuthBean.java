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
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.xml.ws.soap.SOAPFaultException;
import org.cesecore.util.CertTools;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.admin.web.ejb.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;
import org.signserver.admin.web.ejb.NotLoggedInException;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class WorkerAuthBean {

    //@ManagedProperty(value = "#{param.id}")
    private Integer id;

    private String property;
    private String propertyValue;

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private Worker worker;
    private String status;
    private List<KeyValue> config;
    private WorkerConfig workerConfig;

    private String destroyKeyAlias;
    private Integer destroyKeyStep = 0;
    private boolean destroyKeySuccess;
    private String destroyKeyError;

    private String certSN;
    private String issuerDN;
    private String oldCertSN;
    private String oldIssuerDN;

    private String cert;
    private boolean fromCertificate;

    private String loadErrorMessage;

    /**
     * Creates a new instance of WorkerBean
     */
    public WorkerAuthBean() {
    }

    public Worker getWorker() throws AdminNotAuthorizedException, NoSuchWorkerException {
        if (worker == null) {
            Properties config = getWorkerConfig().getProperties();
            final String name = config.getProperty("NAME");
            if (name == null) {
                throw new NoSuchWorkerException(String.valueOf(id));
            }
            worker = new Worker(id, true, name, config);
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

    public String getStatus() throws AdminNotAuthorizedException {
        if (status == null) {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            try {
                workerSessionBean.getStatus(authBean.getAdminCertificate(), new WorkerIdentifier(id)).displayStatus(new PrintStream(bout, false, StandardCharsets.UTF_8.toString()), true);
                status = bout.toString(StandardCharsets.UTF_8.toString());
            } catch (UnsupportedEncodingException | InvalidWorkerIdException ex) {
                throw new IllegalStateException(ex);
            }
        }
        return status;
    }

    public List<KeyValue> getConfig() throws AdminNotAuthorizedException {
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
        sb.append("?faces-redirect=true&amp;workers=").append(id); // TODO: +Going back page / viewing navigation path
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

    public String getLoadErrorMessage() {
        return loadErrorMessage;
    }

    public String editAction() throws AdminNotAuthorizedException {

        final AuthorizedClient oldAuthorizedClient = new AuthorizedClient();
        oldAuthorizedClient.setCertSN(oldCertSN);
        oldAuthorizedClient.setIssuerDN(oldIssuerDN);

        final AuthorizedClient client = new AuthorizedClient();
        final BigInteger sn = new BigInteger(certSN, 16);

        client.setCertSN(sn.toString(16));
        client.setIssuerDN(CertTools.stringToBCDNString(issuerDN));

        boolean removed = workerSessionBean.removeAuthorizedClient(authBean.getAdminCertificate(), worker.getId(), oldAuthorizedClient);
        if (removed) {
            workerSessionBean.addAuthorizedClient(authBean.getAdminCertificate(), worker.getId(), client);
            workerSessionBean.reloadConfiguration(authBean.getAdminCertificate(), worker.getId());
        }

        return "worker-authorization?faces-redirect=true&amp;includeViewParams=true&amp;id=" + id;
    }

    public String addAction() throws AdminNotAuthorizedException {
        final AuthorizedClient client = new AuthorizedClient();
        final BigInteger sn = new BigInteger(certSN, 16);

        client.setCertSN(sn.toString(16));
        client.setIssuerDN(CertTools.stringToBCDNString(issuerDN));

        workerSessionBean.addAuthorizedClient(authBean.getAdminCertificate(), worker.getId(), client);
        workerSessionBean.reloadConfiguration(authBean.getAdminCertificate(), worker.getId());

        return "worker-authorization?faces-redirect=true&amp;includeViewParams=true&amp;id=" + id;
    }

    public void browseAction() {
        fromCertificate = true;
    }
    
    public void loadCurrentAction() throws NotLoggedInException {
        X509Certificate current = getAuthBean().getAdminCertificate();
        certSN = current.getSerialNumber().toString(16);
        issuerDN = CertTools.stringToBCDNString(current.getIssuerX500Principal().getName());
    }

    public void cancelBrowseAction() {
        fromCertificate = false;
    }

    public void loadAction() {
        try {
            final X509Certificate certificate = (X509Certificate) CertTools.getCertfromByteArray(cert.getBytes(StandardCharsets.UTF_8));
            certSN = certificate.getSerialNumber().toString(16);
            issuerDN = CertTools.stringToBCDNString(certificate.getIssuerX500Principal().getName());
            fromCertificate = false;
            loadErrorMessage = null;
        } catch (CertificateParsingException ex) {
            loadErrorMessage = "Unable to load certificate: " + ex.getLocalizedMessage();
        }

    }

    public String addPropertyAction() throws AdminNotAuthorizedException {
        //workerSessionBean.setWorkerProperty(getAuthBean().getAdminCertificate(), id, property, propertyValue);
        return "worker-authorization?faces-redirect=true&amp;includeViewParams=true&amp;id=" + id;
    }

    public String removePropertyAction() throws AdminNotAuthorizedException {
        workerSessionBean.removeAuthorizedClient(getAuthBean().getAdminCertificate(), id, new AuthorizedClient(certSN, issuerDN));
        workerSessionBean.reloadConfiguration(authBean.getAdminCertificate(), worker.getId());
        return "worker-authorization?faces-redirect=true&amp;includeViewParams=true&amp;id=" + id;
    }

    public Collection<AuthorizedClient> getAuthorizedClients() throws AdminNotAuthorizedException {
        return workerSessionBean.getAuthorizedClients(authBean.getAdminCertificate(), id);
    }

    public String getCertSN() {
        return certSN;
    }

    public void setCertSN(String certSN) {
        this.certSN = certSN;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public String getOldCertSN() {
        if (oldCertSN == null) {
            oldCertSN = certSN;
        }
        return oldCertSN;
    }

    public void setOldCertSN(String oldCertSN) {
        this.oldCertSN = oldCertSN;
    }

    public String getOldIssuerDN() {
        if (oldIssuerDN == null) {
            oldIssuerDN = issuerDN;
        }
        return oldIssuerDN;
    }

    public void setOldIssuerDN(String oldIssuerDN) {
        this.oldIssuerDN = oldIssuerDN;
    }

    public String getCert() {
        return cert;
    }

    public void setCert(String cert) {
        this.cert = cert;
    }

    public boolean isFromCertificate() {
        return fromCertificate;
    }

}
