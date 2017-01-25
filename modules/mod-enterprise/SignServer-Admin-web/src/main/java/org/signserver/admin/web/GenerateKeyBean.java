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
import java.util.List;
import java.util.ListIterator;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.admin.web.ejb.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class GenerateKeyBean {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(GenerateKeyBean.class);

    //@ManagedProperty(value = "#{param.id}")
    private Integer id;

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private WorkerConfig workerConfig;

    private List<Item> items;

    /**
     * Creates a new instance of WorkerBean
     */
    public GenerateKeyBean() {
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

    private WorkerConfig getWorkerConfig() throws AdminNotAuthorizedException {
        if (workerConfig == null) {
            workerConfig = workerSessionBean.getCurrentWorkerConfig(authBean.getAdminCertificate(), id);
        }
        return workerConfig;
    }

    public List<Item> getItems() throws AdminNotAuthorizedException {
        if (items == null) {
            items = new ArrayList<>();
            // One initial and empty item
            Item item = new Item(getWorkerConfig());
            item.setFirst(true);
            items.add(item);
        }
        return items;
    }

    public void setItems(List<Item> items) {
        this.items = items;
    }

    public void addAction() throws AdminNotAuthorizedException {
        final Item item = new Item(getWorkerConfig());
        if (items.isEmpty()) {
            item.setFirst(true);
        } else {
            items.get(items.size() - 1).setLast(false);
        }
        items.add(item);
    }

    public void removeAction() {
        if (items.size() > 1) {
            items.remove(items.size() - 1);
            items.get(items.size() - 1).setLast(true);
        }
    }

    private static boolean isEmpty(String s) {
        return s == null || s.trim().isEmpty();
    }

    public String submitAction() throws AdminNotAuthorizedException {
        ListIterator<Item> it = items.listIterator();
        while (it.hasNext()) {
            Item item = it.next();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Key generation: worker=" + id
                        + ", keyAlg=" + item.getKeyAlg() + ", keySpec="
                        + item.getKeySpec() + ", alias: " + item.getAlias());
            }

            if (isEmpty(item.getAlias()) || isEmpty(item.getKeyAlg()) || isEmpty(item.getKeySpec()) || isEmpty(item.getAlias())) {
                item.setErrorMessage("Please, fill in all required fields");
                continue;
            }

            String newAlias = null;
            try {
                // Generate key
                newAlias = workerSessionBean.generateSignerKey(authBean.getAdminCertificate(),
                        new WorkerIdentifier(id), item.getKeyAlg(), item.getKeySpec(), item.getAlias(), "");

                if (newAlias == null) {
                    item.setErrorMessage("Could not generate key");
                }
            } catch (EJBException eJBException) {
                if (eJBException.getCausedByException() instanceof IllegalArgumentException) {
                    item.setErrorMessage(eJBException.getCausedByException().getMessage());
                    LOG.error("Error generating key", eJBException);
                } else {
                    item.setErrorMessage(eJBException.getMessage());
                    LOG.error("Error generating key", eJBException);
                }
            } catch (CryptoTokenOfflineException | InvalidWorkerIdException e) {
                item.setErrorMessage(e.getMessage());
                LOG.error("Error generating key", e);
            }

            if (newAlias != null) {

                LOG.debug("Created key " + newAlias + " for signer "
                        + id);

                it.remove();
            }
        }

        return items.isEmpty() ? "worker-cryptotoken?faces-redirect=true&amp;includeViewParams=true&amp;id=" + id : null;
    }

    public static class Item {

        private String alias;
        private String keyAlg;
        private String keySpec;
        private boolean first;
        private boolean last = true;
        private String errorMessage;

        public Item(WorkerConfig config) {
            this.keyAlg = config.getProperty("KEYALG");
            this.keySpec = config.getProperty("KEYSPEC");
        }

        public String getAlias() {
            return alias;
        }

        public void setAlias(String alias) {
            this.alias = alias;
        }

        public String getKeyAlg() {
            return keyAlg;
        }

        public void setKeyAlg(String keyAlg) {
            this.keyAlg = keyAlg;
        }

        public String getKeySpec() {
            return keySpec;
        }

        public void setKeySpec(String keySpec) {
            this.keySpec = keySpec;
        }

        public boolean isLast() {
            return last;
        }

        public void setLast(boolean last) {
            this.last = last;
        }

        public boolean isFirst() {
            return first;
        }

        public void setFirst(boolean first) {
            this.first = first;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public void setErrorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
        }

    }
}
