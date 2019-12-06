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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Objects;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.xml.ws.soap.SOAPFaultException;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class ImportCertificatesBean extends BulkBean {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ImportCertificatesBean.class);

    //@ManagedProperty(value = "#{param.id}")
    private Integer id;

    @EJB
    private AdminWebSessionBean workerSessionBean;

    private List<Item> items;

    private List<String> keysList;
    private String keys;

    /**
     * Creates a new instance of WorkerBean
     */
    public ImportCertificatesBean() {
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Integer getId() {
        return id;
    }

    public List<Item> getItems() throws AdminNotAuthorizedException {
        if (items == null) {
            List<String> ks = getKeysList();
            items = new ArrayList<>(ks.size());
            int index = 0;
            for (String k : ks) {
                items.add(new Item(k, index++));
            }
        }
        return items;
    }

    public String getKeys() {
        return keys;
    }

    public void setKeys(String keys) {
        this.keys = keys;
    }

    public List<String> getKeysList() {
        if (keysList == null) {
            keysList = new ArrayList<>();
            if (keys != null) {
                String[] split = keys.split(",");
                keysList = Arrays.asList(split);
            }
        }
        return keysList;
    }

    public String submitAction() throws AdminNotAuthorizedException {
        ListIterator<Item> it = items.listIterator();
        while (it.hasNext()) {
            Item worker = it.next();

            ArrayList<Certificate> signerChain = worker.getCertificates();
            try {
                if (signerChain.isEmpty()) {
                    final String error
                            = "Problem with certificate chain file: No certificates in file";
                    LOG.error(error);
                    worker.setErrorMessage(error);
                } else {
                    worker.setErrorMessage("");

                    List<byte[]> signerChainBytes = asByteArrayList(signerChain);

                    workerSessionBean.importCertificateChain(getAuthBean().getAdminCertificate(), id,
                            signerChainBytes,
                            worker.getAlias(), null);

                    it.remove();
                }
            } catch (AdminNotAuthorizedException ex) {
                final String error
                        = "Authorization denied: " + ex.getMessage();
                worker.setErrorMessage(error);
            } catch (CertificateParsingException ex) {
                worker.setErrorMessage("Unable to parse certificate: " + ex.getMessage());
            } catch (SOAPFaultException | EJBException | CryptoTokenOfflineException | CertificateException ex) {
                final String error
                        = "Operation failed on server side: " + ex.getMessage();
                LOG.error(error, ex);
                worker.setErrorMessage(error);
            } catch (OperationUnsupportedException ex) {
                worker.setErrorMessage("Importing certificate chain is not supported by crypto token: " + ex.getMessage());
            }
        }

        return items.isEmpty() ? "worker-cryptotoken?faces-redirect=true&amp;includeViewParams=true&amp;id=" + id : null;
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

    public static class Item {

        private final String alias;
        private String signerCert;
        private String certificateChain;
        private final ArrayList<Certificate> certificates = new ArrayList<>();
        private final int rowIndex;
        private String errorMessage;

        public Item(String alias, int rowIndex) {
            this.alias = alias;
            this.rowIndex = rowIndex;
        }

        public String getAlias() {
            return alias;
        }

        public String getSignerCert() {
            return signerCert;
        }

        public void setSignerCert(String signerCert) {
            this.signerCert = signerCert;
        }

        public String getCertificateChain() {
            return certificateChain;
        }

        public void setCertificateChain(String certificateChain) {
            this.certificateChain = certificateChain;
        }

        public ArrayList<Certificate> getCertificates() {
            return certificates;
        }

        public int getRowIndex() {
            return rowIndex;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public void setErrorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
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

        public void uploadAction() {
            try {
                List<Certificate> certsFromPEM = CertTools.getCertsFromPEM(new ByteArrayInputStream(certificateChain.getBytes(StandardCharsets.US_ASCII)));
                certificates.addAll(certsFromPEM);
                certificateChain = ""; // Clear text area
                errorMessage = "";
            } catch (CertificateParsingException ex) {
                errorMessage = ex.getMessage();
            }
        }
        
        public void removeCertificateAction(CertificateItem item) {
            certificates.remove(item.getCertificate());
            errorMessage = "";
        }
        
        public static class CertificateItem {
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
