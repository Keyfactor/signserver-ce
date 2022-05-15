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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.signserver.admin.common.query.QueryCondition;
import org.signserver.admin.common.query.QueryOrdering;
import org.signserver.admin.common.query.QueryOrdering.Order;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.QueryException;
import org.signserver.common.SignServerException;
import org.signserver.server.cryptotokens.TokenEntry;
import org.signserver.server.cryptotokens.TokenSearchResults;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;
import org.signserver.server.cryptotokens.CryptoTokenHelper;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class CryptoTokenBean {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CryptoTokenBean.class);

    //@ManagedProperty(value = "#{param.id}")
    private Integer id;

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private final PaginationSupport pagination = new PaginationSupport();
    private List<Entry> entries;
    private String queryError;
    
    private String[] keysSelected = new String[0];

    /**
     * Creates a new instance of WorkerBean
     */
    public CryptoTokenBean() {
    }

    public void init() throws AdminNotAuthorizedException {
        // Get selected keys: There can be multiple "selected" params.
        String[] selected = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterValuesMap().get("selected");
        if (selected != null) {
            keysSelected = selected;
        }
        getEntries();
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

    public List<Entry> getEntries() throws AdminNotAuthorizedException {
        if (entries == null) {
            queryError = null;
            QueryOrdering ordering = new QueryOrdering();
            ordering.setOrder(Order.ASC);
            ordering.setColumn(CryptoTokenHelper.TokenEntryFields.keyAlias.name());

            if (id == null) {
                queryError = "No such worker";
            } else {
                Boolean moreAvailable = null;
                try {
                    TokenSearchResults results = workerSessionBean.queryTokenEntries(authBean.getAdminCertificate(),
                            id,
                            pagination.getFromIndex(), pagination.getMaxEntries(),
                            Collections.<QueryCondition>emptyList(),
                            Arrays.asList(ordering),
                            true);
                    if (results == null) {
                        entries = Collections.emptyList();
                    } else {
                        entries = convert(results.getEntries());
                        moreAvailable = results.isMoreEntriesAvailable();
                    }
                    pagination.updateResults(entries.size(), moreAvailable);

                } catch (OperationUnsupportedException | CryptoTokenOfflineException | QueryException | InvalidWorkerIdException | AuthorizationDeniedException | SignServerException ex) {
                    queryError = ex.getMessage();
                    LOG.error("Reload failed within the selected interval: " + ex.getMessage(), ex);
                }
            }
        }
        return entries;
    }

    private List<Entry> convert(List<TokenEntry> tes) {
        final ArrayList<Entry> results = new ArrayList<>(tes.size());
        final Set<String> selectedKeys = new HashSet<>(Arrays.asList(keysSelected));
        for (TokenEntry te : tes) {
            results.add(Entry.fromTokenEntry(te, selectedKeys.contains(te.getAlias())));
        }
        return results;
    }

    public String getQueryError() {
        return queryError;
    }

    public Integer getFromIndex() throws AdminNotAuthorizedException {
        if (entries == null) {
            getEntries();
        }
        return pagination.getFromIndex() + 1;
    }

    public void setFromIndex(Integer fromIndex) {
        pagination.setFromIndex(fromIndex - 1);
    }

    public void reloadAction() {
        entries = null;
    }

    public void firstAction() {
        pagination.goToFirst();
        reloadAction();
    }

    public void previousAction() {
        pagination.goBackwards();

        // Reload
        reloadAction();
    }

    public void nextAction() {
        pagination.goForward();

        // Reload
        reloadAction();
    }

    private List<String> getSelectedKeys() {
        final List<String> keys = new ArrayList<>();
        if (entries != null) {
            for (Entry entry : entries) {
                if (entry.isSelected()) {
                    keys.add(entry.getAlias());
                }
            }
        }
        return keys;
    }

    public String generateCSRAction() {
        final List<String> keys = getSelectedKeys();
        StringBuilder sb = new StringBuilder();
        if (!keys.isEmpty()) {
            sb.append("worker-cryptotoken-csr");
            sb.append("?faces-redirect=true&amp;id=").append(String.valueOf(id));
            sb.append("&amp;workers=").append(StringUtils.repeat(String.valueOf(id), ",", keys.size())); // TODO: +Going back page / viewing navigation path
            sb.append("&amp;keys=").append(StringUtils.join(keys, ","));
        }
        return sb.toString();
    }

    public String certificatesAction() {
        final List<String> keys = getSelectedKeys();
        StringBuilder sb = new StringBuilder();
        if (!keys.isEmpty()) {
            sb.append("worker-cryptotoken-certificates");
            sb.append("?faces-redirect=true&amp;id=").append(String.valueOf(id));
            sb.append("&amp;keys=").append(StringUtils.join(keys, ","));
        }
        return sb.toString();
    }

    public String testKeysAction() {
        final List<String> keys = getSelectedKeys();
        StringBuilder sb = new StringBuilder();
        if (!keys.isEmpty()) {
            sb.append("worker-cryptotoken-testkeys");
            sb.append("?faces-redirect=true&amp;id=").append(String.valueOf(id)).append("&amp;workers=").append(StringUtils.repeat(String.valueOf(id), ",", keys.size()));
            sb.append("&amp;keys=").append(StringUtils.join(keys, ","));
            sb.append("&amp;previous=cryptotoken");
        }
        return sb.toString();
    }

    public String removeKeysAction() {
        final List<String> keys = getSelectedKeys();
        StringBuilder sb = new StringBuilder();
        if (!keys.isEmpty()) {
            sb.append("worker-cryptotoken-removekeys");
            sb.append("?faces-redirect=true&amp;id=").append(String.valueOf(id));
            sb.append("&amp;keys=").append(StringUtils.join(keys, ","));
        }
        return sb.toString();
    }

    public static class Entry {
        
        private static final String SPACE = " ";

        private static final Map<String, String> TYPE_TITLES = new HashMap<>();

        static {
            TYPE_TITLES.put(TokenEntry.TYPE_PRIVATEKEY_ENTRY, "Asymmetric");
            TYPE_TITLES.put(TokenEntry.TYPE_SECRETKEY_ENTRY, "Symmetric");
            TYPE_TITLES.put(TokenEntry.TYPE_TRUSTED_ENTRY, "Trusted");
        }

        private final String alias;
        private final String type;
        private final int chainLength;
        private boolean selected;

        public Entry(String alias, String type, int chainLength, boolean selected) {
            this.alias = alias;
            this.type = type;
            this.chainLength = chainLength;
            this.selected = selected;
        }

        public static Entry fromTokenEntry(TokenEntry te, boolean selected) {
            return new Entry(te.getAlias(), getKeyAlgoAndSpec(te.getInfo()), te.getChain().length, selected);
        }        
        
        // Method to get Key Algorithm and Specification for particular Crypto token entry
        private static String getKeyAlgoAndSpec(Map<String, String> info) {

            String keyAlgo = null;
            String keySpec = null;
            String keyAlgoWithSpec;

            if (info != null) {
                keyAlgo = info.get(CryptoTokenHelper.INFO_KEY_ALGORITHM);
                keySpec = info.get(CryptoTokenHelper.INFO_KEY_SPECIFICATION);
            }

            keyAlgoWithSpec =
                    keySpec != null ? keyAlgo + SPACE + keySpec : keyAlgo;
            return keyAlgoWithSpec;
        }

        public String getAlias() {
            return alias;
        }

        public String getType() {
            return type;
        }

        public int getChainLength() {
            return chainLength;
        }

        public boolean isSelected() {
            return selected;
        }

        public void setSelected(boolean selected) {
            this.selected = selected;
        }

    }

    public Integer getMaxEntries() {
        return pagination.getMaxEntries();
    }

    public void setMaxEntries(Integer numEntries) {
        pagination.setMaxEntries(numEntries);
    }

    public Integer getQueryingToIndex() throws AdminNotAuthorizedException {
        if (entries == null) {
            getEntries();
        }
        return pagination.getQueryingToIndex();
    }

    public boolean isEnableFirst() throws AdminNotAuthorizedException {
        if (entries == null) {
            getEntries();
        }
        return pagination.isEnableFirst();
    }

    public boolean isEnablePrevious() throws AdminNotAuthorizedException {
        if (entries == null) {
            getEntries();
        }
        return pagination.isEnablePrevious();
    }

    public boolean isEnableNext() throws AdminNotAuthorizedException {
        if (entries == null) {
            getEntries();
        }
        return pagination.isEnableNext();
    }
}