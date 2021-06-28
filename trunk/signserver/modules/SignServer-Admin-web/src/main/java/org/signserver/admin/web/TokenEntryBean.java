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

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.CertTools;
import org.cesecore.util.query.elems.RelationalOperator;
import org.signserver.admin.common.query.QueryCondition;
import org.signserver.admin.common.query.QueryOrdering;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.QueryException;
import org.signserver.common.SignServerException;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import org.signserver.server.cryptotokens.TokenEntry;
import org.signserver.server.cryptotokens.TokenSearchResults;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class TokenEntryBean {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TokenEntryBean.class);

    private static final FastDateFormat FDF = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ss zz");
    
    public static final String NOT_APPLICABLE = "n/a";

    //@ManagedProperty(value = "#{param.id}")
    private Integer id;

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private List<Item> items;

    private String key;
    private TokenEntry entry;
    private String errorMessage;

    private List<X509Certificate> chain;

    /**
     * Creates a new instance of WorkerBean
     */
    public TokenEntryBean() {
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
        if (id == null) {
            id = 0;
        }
        return id;
    }

    private TokenEntry getEntry() throws AdminNotAuthorizedException {
        if (entry == null) {
            try {
                TokenSearchResults search = workerSessionBean.queryTokenEntries(authBean.getAdminCertificate(), getId(), 0, 1, Arrays.asList(new QueryCondition(CryptoTokenHelper.TokenEntryFields.keyAlias.name(), RelationalOperator.EQ, key)), Collections.<QueryOrdering>emptyList(), true);
                if (search.getEntries().isEmpty()) {
                    errorMessage = "No result";
                } else {
                    entry = search.getEntries().get(0);
                    errorMessage = null;
                }
            } catch (OperationUnsupportedException | CryptoTokenOfflineException | QueryException | InvalidWorkerIdException | AuthorizationDeniedException | SignServerException ex) {
                errorMessage = "Error: " + ex.getMessage();
                LOG.error(errorMessage, ex);
            }
        }
        return entry;
    }

    public List<Item> getItems() throws AdminNotAuthorizedException {
        if (items == null) {
            items = new ArrayList<>();

            TokenEntry et = getEntry();

            if (et != null) {
                X509Certificate signerCert = null;
                boolean showCertificateViewLink = true;
                try {
                    if (et.getChain() != null && et.getChain().length != 0) {
                        this.chain = new LinkedList<>();
                        for (byte[] certBytes : et.getChain()) {
                            Certificate cert = CertTools.getCertfromByteArray(certBytes, "BC");
                            if (cert instanceof X509Certificate) {
                                this.chain.add((X509Certificate) cert);
                            } else {
                                LOG.info("Not an X.509 certificate: " + cert);
                            }
                        }
                        signerCert = this.chain.get(0);
                    } else if (et.getTrustedCertificate() != null && et.getTrustedCertificate().length > 0) {
                        this.chain = new LinkedList<>();
                        Certificate cert = CertTools.getCertfromByteArray(et.getTrustedCertificate(), "BC");
                        if (cert instanceof X509Certificate) {
                            this.chain.add((X509Certificate) cert);
                        } else {
                            LOG.info("Not an X.509 certificate: " + cert);
                        }
                    }
                } catch (CertificateException ex) {
                    LOG.error("Unable to parse certificate from token: " + ex.getMessage(), ex);
                    this.chain = null;
                }

                final String alias = et.getAlias();
                final String type = et.getType();
                final String creationDate = et.getCreationDate() == null ? "n/a" : FDF.format(et.getCreationDate());

                final String certSubjectDN;
                if (signerCert != null) {
                    certSubjectDN = CertTools.getSubjectDN(signerCert);
                } else if (chain != null) { // For trusted certificates
                    // As of now TokenEntry certificate chain is empty for trusted entries 
                    certSubjectDN = NOT_APPLICABLE;
                    // certSubjectDN = CertTools.getSubjectDN(chain.get(0));
                    showCertificateViewLink = false;
                } else {
                    certSubjectDN = NOT_APPLICABLE;
                    showCertificateViewLink = false;
                }
                
                items.add(new Item("Alias", alias));
                items.add(new Item("Type", type));
                items.add(new Item("Creation date", creationDate));
                items.add(new Item("Certificate", certSubjectDN, showCertificateViewLink));

                if (et.getInfo() != null) {
                    for (Entry<String, String> item : et.getInfo().entrySet()) {
                        items.add(new Item(item.getKey(), item.getValue()));
                    }
                }
            }
        }
        return items;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = StringUtils.trim(key);
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public static class Item {

        private final String key;
        private final String value;
        private final boolean certificate;

        public Item(String key, String value) {
            this(key, value, false);
        }

        public Item(String key, String value, boolean certificate) {
            this.key = key;
            this.value = value;
            this.certificate = certificate;
        }

        public String getKey() {
            return key;
        }

        public String getValue() {
            return value;
        }

        public boolean isCertificate() {
            return certificate;
        }

    }
}
