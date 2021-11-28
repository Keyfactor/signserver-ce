/** ***********************************************************************
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
 ************************************************************************ */
package org.signserver.admin.web;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.Optional;
import javax.ejb.EJBException;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.xml.ws.soap.SOAPFaultException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.WorkerConfig;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.NotLoggedInException;
import org.signserver.common.InvalidWorkerIdException;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class CertificatesBulkBean extends BulkBean {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(CertificatesBulkBean.class);

    private List<CertificatesWorker> myWorkers;

    /**
     * Creates a new instance of WorkersManagedBean
     */
    public CertificatesBulkBean() {

    }

    public List<CertificatesWorker> getCertificatesWorkers() throws AdminNotAuthorizedException {
        if (myWorkers == null) {
            myWorkers = new ArrayList<>();
            int index = 0;
            for (int id : getWorkerIdsList()) {
                WorkerConfig config = getWorkerSessionBean().getCurrentWorkerConfig(getAuthBean().getAdminCertificate(), id);
                String name = config.getProperty("NAME");
                boolean exists = true;
                if (name == null) {
                    name = "Not Found";
                    exists = false;
                }
                String alias = config.getProperty("NEXTCERTSIGNKEY");
                if (alias == null) {
                    alias = config.getProperty("DEFAULTKEY");
                }
                if (alias == null) {
                    alias = "all";
                }

                myWorkers.add(new CertificatesWorker(id, exists, name, config.getProperties(), alias, index++));

                // Select checkbox
                getSelectedIds().put(id, exists);
            }
        }
        return myWorkers;
    }

    public List<CertificatesWorker> getSelectedCertificatesWorkers() throws AdminNotAuthorizedException {
        final ArrayList<CertificatesWorker> results = new ArrayList<>(getSelectedIds().size());
        for (CertificatesWorker worker : getCertificatesWorkers()) {
            if (Boolean.TRUE.equals(getSelectedIds().get(worker.getId()))) {
                results.add(worker);
            }
        }
        return results;
    }
    
    public String installAction() throws AdminNotAuthorizedException {
        // TODO: We should consider using faces message for the errors:
        //FacesMessage errorMessage = new FacesMessage("Test error");
        //errorMessage.setSeverity(FacesMessage.SEVERITY_ERROR);
        //FacesContext.getCurrentInstance().addMessage(null, errorMessage);

        for (CertificatesWorker worker : getSelectedCertificatesWorkers()) {

            try {
                final String scope = GlobalConfiguration.SCOPE_GLOBAL;

                ArrayList<Certificate> signerChain = worker.getCertificates();

                if (signerChain.isEmpty()) {
                    final String error
                            = "Problem with certificate chain file: No certificates in file";
                    LOG.error(error);
                    worker.setSuccess(null);
                    worker.setError(error);
                } else {

                    Certificate signerCert = signerChain.get(0);
                    List<byte[]> signerChainBytes = asByteArrayList(signerChain);

                    if (worker.isInToken()) {

                        getWorkerSessionBean().importCertificateChain(getAuthBean().getAdminCertificate(), worker.getId(),
                                signerChainBytes,
                                worker.getAlias(), null);
                    } else {
                        getWorkerSessionBean().uploadSignerCertificateChain(getAuthBean().getAdminCertificate(), worker.getId(), signerChainBytes, scope);
                        getWorkerSessionBean().uploadSignerCertificate(getAuthBean().getAdminCertificate(), worker.getId(), asByteArray(signerCert), scope);
                    }

                    // Set DEFAULTKEY to NEXTCERTSIGNKEY
                    if (worker.isAliasDefaultKey()) {
                        LOG.debug("Uploaded was for DEFAULTKEY");
                    } else if (worker.isAliasNextKey()) {
                        LOG.debug("Uploaded was for NEXTCERTSIGNKEY");
                        final String nextCertSignKey
                                = worker.getConfig()
                                        .getProperty("NEXTCERTSIGNKEY");
                        getWorkerSessionBean().setWorkerProperty(getAuthBean().getAdminCertificate(), worker.getId(), "DEFAULTKEY", nextCertSignKey);
                        getWorkerSessionBean().removeWorkerProperty(getAuthBean().getAdminCertificate(), worker.getId(), "NEXTCERTSIGNKEY");
                    } else {
                        getWorkerSessionBean().setWorkerProperty(getAuthBean().getAdminCertificate(), worker.getId(), "DEFAULTKEY", worker.getAlias());
                    }
                    getWorkerSessionBean().reloadConfiguration(getAuthBean().getAdminCertificate(), worker.getId());

                    getSelectedIds().remove(worker.getId());
                    worker.setError(null);
                    worker.setSuccess("Installed");
                }
            } catch (AdminNotAuthorizedException ex) {
                final String error
                        = "Authorization denied: " + ex.getMessage();
                worker.setError(error);
                worker.setSuccess(null);
            } catch (CertificateParsingException ex) {
                worker.setError("Unable to parse certificate: " + ex.getMessage());
                worker.setSuccess(null);
            } catch (SOAPFaultException | EJBException | CryptoTokenOfflineException | CertificateException ex) {
                final String error
                        = "Operation failed on server side: " + ex.getMessage();
                LOG.error(error, ex);
                worker.setError(error);
                worker.setSuccess(null);
            } catch (IllegalRequestException ex) {
                final String error
                        = "Problem with certificates: " + ex.getMessage();
                LOG.error(error, ex);
                worker.setError(error);
                worker.setSuccess(null);
            } catch (OperationUnsupportedException ex) {
                worker.setError("Importing certificate chain is not supported by crypto token: " + ex.getMessage());
                worker.setSuccess(null);
            }
        }

        if (getSelectedIds().isEmpty()) {
            return "workers?faces-redirect=true&amp;includeViewParams=true&amp;" + "selected=" + StringUtils.join(getWorkerIdsList(), ",");
        } else {
            return "";
        }
    }

    private List<byte[]> asByteArrayList(
            final List<Certificate> signerChain)
            throws CertificateEncodingException {
        final List<byte[]> result = new LinkedList<>();
        for (final Certificate cert : signerChain) {
            result.add(cert.getEncoded());
        }
        return result;
    }

    private byte[] asByteArray(final Certificate signerCert)
            throws CertificateEncodingException {
        return signerCert.getEncoded();
    }

    public class CertificatesWorker extends Worker {

        private String alias;
        private String signerCert;
        private String certificateChain;
        private final ArrayList<Certificate> certificates = new ArrayList<>();
        private List<String> certificateIssues;
        private String errorMessage;

        //private UploadedFile uploadedFile;
        private final int rowIndex;
        private boolean showOther;
        private List<SelectItem> aliasMenuValues;
        private boolean inToken;

        public CertificatesWorker(int id, boolean exists, String name, Properties config, String alias, int rowIndex) {
            super(id, exists, name, config);
            this.alias = alias;
            this.rowIndex = rowIndex;
            if (alias == null) {
                showOther = true;
            }
        }

        public String getAlias() {
            return alias;
        }

        public void setAlias(String alias) {
            this.alias = StringUtils.trim(alias);
        }

        public String getSignerCert() {
            return signerCert;
        }

        public void setSignerCert(String signerCert) {
            this.signerCert = StringUtils.trim(signerCert);
        }

        public String getCertificateChain() {
            return certificateChain;
        }

        public void setCertificateChain(String certificateChain) {
            this.certificateChain = StringUtils.trim(certificateChain);
        }

        public ArrayList<Certificate> getCertificates() {
            return certificates;
        }

        public boolean isShowOther() {
            return showOther;
        }

        public void setShowOther(boolean showOther) {
            this.showOther = showOther || alias == null || alias.isEmpty();
            aliasMenuValues = null;
        }

        public int getRowIndex() {
            return rowIndex;
        }

        public List<SelectItem> getAliasMenuValues() {
            if (aliasMenuValues == null) {
                aliasMenuValues = new ArrayList<>();
                Properties config = getConfig();
                String defaultKey = config.getProperty("DEFAULTKEY");
                if (defaultKey != null) {
                    aliasMenuValues.add(new SelectItem("Default key (" + defaultKey + ")", defaultKey));
                }
                String nextKey = config.getProperty("NEXTCERTSIGNKEY");
                if (nextKey != null) {
                    aliasMenuValues.add(new SelectItem("Next key (" + nextKey + ")", nextKey));
                }
                if (alias != null && !alias.equals(defaultKey) && !alias.equals(nextKey)) {
                    aliasMenuValues.add(new SelectItem("Other key (" + alias + ")", alias));
                }
            }
            return aliasMenuValues;
        }

        public String getAliasMenuValuesFirst() {
            Optional<SelectItem> first = aliasMenuValues.stream().findFirst();
            return first.get().getItemLabel();
        }

        public boolean isInToken() {
            return inToken;
        }

        public void setInToken(boolean inToken) {
            this.inToken = inToken;
        }

        public boolean isAliasDefaultKey() {
            return alias != null && alias.equals(getConfig().getProperty("DEFAULTKEY"));
        }

        public boolean isAliasNextKey() {
            return alias != null && alias.equals(getConfig().getProperty("NEXTCERTSIGNKEY"));
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public List<CertificateItem> getFriendlyCertificates() {
            final ArrayList<CertificateItem> result = new ArrayList<>(certificates.size());
            for (Certificate cert : certificates) {
                if (cert instanceof X509Certificate) {
                    X509Certificate xc = (X509Certificate) cert;
                    result.add(new CertificateItem(xc.getSubjectX500Principal().getName(), xc));
                }
            }
            return result;
        }
        
        public List<String> getCertificateIssues() throws InvalidWorkerIdException, NotLoggedInException, AdminNotAuthorizedException {
            if (certificateIssues == null) {
                certificateIssues = getWorkerSessionBean().getCertificateIssues(getAuthBean().getAdminCertificate(), getId(), certificates);
            }
            return certificateIssues;
        }

        public void uploadAction() {
            try {
                List<Certificate> certsFromPEM = CertTools.getCertsFromPEM(new ByteArrayInputStream(certificateChain.getBytes(StandardCharsets.US_ASCII)));
                certificates.addAll(certsFromPEM);
                certificateChain = ""; // Clear text area
                certificateIssues = null;
            } catch (CertificateParsingException ex) {
                errorMessage = ex.getMessage();
            }
        }
        
        public void removeCertificateAction(CertificateItem item) {
            certificates.remove(item.getCertificate());
            certificateIssues = null;
        }
        
        public class CertificateItem {
            private final String name;
            private final X509Certificate certificate;

            public CertificateItem(String name, X509Certificate certificate) {
                this.name = name;
                this.certificate = certificate;
            }

            @Override
            public int hashCode() {
                int hash = 7;
                hash = 37 * hash + Objects.hashCode(this.name);
                hash = 37 * hash + Objects.hashCode(this.certificate);
                return hash;
            }

            @Override
            public boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                if (obj == null) {
                    return false;
                }
                if (getClass() != obj.getClass()) {
                    return false;
                }
                final CertificateItem other = (CertificateItem) obj;
                if (!Objects.equals(this.name, other.name)) {
                    return false;
                }
                if (!Objects.equals(this.certificate, other.certificate)) {
                    return false;
                }
                return true;
            }

            public String getName() {
                return name;
            }

            public X509Certificate getCertificate() {
                return certificate;
            }
            
        }
        
    }
}
