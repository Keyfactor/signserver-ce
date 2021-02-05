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

import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ListIterator;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.xml.ws.soap.SOAPFaultException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.SignServerException;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RemoveKeysBean extends BulkBean {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(RemoveKeysBean.class);

    //@ManagedProperty(value = "#{param.id}")
    private Integer id;

    @EJB
    private AdminWebSessionBean workerSessionBean;

    private List<Item> items;

    private List<String> keysList;
    private String keys;

    private boolean done;

    /**
     * Creates a new instance of WorkerBean
     */
    public RemoveKeysBean() {
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
        this.keys = StringUtils.trim(keys);
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

    public String destroyAction() throws AdminNotAuthorizedException {
        ListIterator<Item> it = items.listIterator();
        boolean anyFailure = false;
        while (it.hasNext()) {
            Item worker = it.next();
            if (worker.getSuccessMessage() == null) {
                try {
                    if (workerSessionBean.removeKey(getAuthBean().getAdminCertificate(), id, worker.getAlias())) {
                        worker.setSuccessMessage("Removed");
                    } else {
                        worker.setSuccessMessage(null);
                        worker.setErrorMessage("Not removed");
                    }
                } catch (AdminNotAuthorizedException ex) {
                    worker.setSuccessMessage(null);
                    worker.setErrorMessage("Authorization denied:\n" + ex.getLocalizedMessage());
                } catch (CryptoTokenOfflineException ex) {
                    worker.setSuccessMessage(null);
                    worker.setErrorMessage("Unable to remove key because token was not active:\n" + ex.getLocalizedMessage());
                } catch (InvalidWorkerIdException | KeyStoreException | SignServerException | SOAPFaultException | EJBException ex) {
                    worker.setSuccessMessage(null);
                    worker.setErrorMessage("Unable to remove key:\n" + ex.getLocalizedMessage());
                }

                anyFailure = anyFailure || worker.getErrorMessage() != null;
            }

        }

        done = !anyFailure;

        return null;
    }

    public boolean isDone() {
        return done;
    }

    public String cancelAction() {
        return "worker-cryptotoken?faces-redirect=true&amp;includeViewParams=true&amp;id=" + id;
    }

    public static class Item {

        private final String alias;
        private final int rowIndex;
        private String errorMessage;
        private String successMessage;

        public Item(String alias, int rowIndex) {
            this.alias = alias;
            this.rowIndex = rowIndex;
        }

        public String getAlias() {
            return alias;
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

        public String getSuccessMessage() {
            return successMessage;
        }

        public void setSuccessMessage(String successMessage) {
            this.successMessage = successMessage;
        }

    }
}
