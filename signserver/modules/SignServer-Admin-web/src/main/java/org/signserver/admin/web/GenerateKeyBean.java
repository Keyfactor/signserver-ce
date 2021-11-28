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
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.common.config.RekeyUtil;
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
        if (id == null) {
            id = 0;
        }
        return id;
    }

    private WorkerConfig getWorkerConfig() throws AdminNotAuthorizedException {
        if (workerConfig == null) {
            workerConfig = workerSessionBean.getCurrentWorkerConfig(authBean.getAdminCertificate(), getId());
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
        Item lastItem = items.get(items.size() - 1);

        int keysToBeGeneratedInteger = -1;
        
        try {
            keysToBeGeneratedInteger = Integer.parseInt(lastItem.getKeysToBeGenerated());

            if (keysToBeGeneratedInteger < 1) {
                lastItem.setLast(true);
                lastItem.setErrorMessage("Number of rows to be added must be > 0");
            } else if (keysToBeGeneratedInteger > 99) {
                lastItem.setLast(true);
                lastItem.setErrorMessage("Number of rows to be added must be < 100");
            } else {
                String keyAlias = lastItem.getAlias();
                String keyAlg = lastItem.getKeyAlg();
                String keySpec = lastItem.getKeySpec();
                boolean selectAlgFromList = lastItem.selectAlgFromList;
                boolean selectKeySpecFromList = lastItem.selectKeySpecFromList;
                String tmpKeyAlias = keyAlias;

                if (!items.isEmpty()) {
                    for (Item item : items) {
                        item.setLast(false);
                        item.setErrorMessage(null);
                    }
                }

                for (int i = 1; i <= keysToBeGeneratedInteger; i++) {
                    final Item item = new Item(getWorkerConfig());

                    if (!StringUtils.isBlank(keyAlias)) {
                        tmpKeyAlias = RekeyUtil.nextAliasInSequence(tmpKeyAlias);
                        item.setAlias(tmpKeyAlias);
                    }

                    item.setKeyAlg(keyAlg);
                    item.setKeySpec(keySpec);
                    item.setSelectAlgFromList(selectAlgFromList);
                    item.setSelectKeySpecFromList(selectKeySpecFromList);

                    if (items.isEmpty()) {
                        item.setFirst(true);
                    }

                    if (i < keysToBeGeneratedInteger) {
                        item.setLast(false);
                    }
                    items.add(item);
                }
            }
        } catch (NumberFormatException ex) {
            lastItem.setLast(true);
            lastItem.setErrorMessage("Number of rows to be added must be a number > 0");
        }
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
        Item rowWithNoData = null;
        boolean showErrors;
        boolean showErrorForNoDataRow = false;
        boolean validRowFound = false;
        boolean rowWithNotAllData = false;
        boolean ejbErrors = false;
        String errorMessage = "Please, fill in all required fields";

        ListIterator<Item> it = items.listIterator();
        while (it.hasNext()) {
            Item item = it.next();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Key generation: worker=" + getId()
                        + ", keyAlg=" + item.getKeyAlg() + ", keySpec="
                        + item.getKeySpec() + ", alias: " + item.getAlias());
            }

            int emptyFieldsCount = getNoOfEmptyFields(item);
            if (emptyFieldsCount > 0) {
                if (emptyFieldsCount < 3) {
                    item.setErrorMessage(errorMessage);
                    rowWithNotAllData = true;
                }
                if (emptyFieldsCount == 3 && rowWithNoData == null) {
                    rowWithNoData = item;
                }
                continue;
            }

            String newAlias = null;
            try {
                // Generate key
                newAlias = workerSessionBean.generateSignerKey(authBean.getAdminCertificate(),
                        new WorkerIdentifier(getId()), item.getKeyAlg(), item.getKeySpec(), item.getAlias(), "");

                if (newAlias == null) {
                    item.setErrorMessage("Could not generate key");
                    ejbErrors = true;
                }
            } catch (EJBException eJBException) {
                if (eJBException.getCausedByException() instanceof IllegalArgumentException) {
                    item.setErrorMessage(eJBException.getCausedByException().getMessage());
                    LOG.error("Error generating key", eJBException);
                    ejbErrors = true;
                } else {
                    item.setErrorMessage(eJBException.getMessage());
                    LOG.error("Error generating key", eJBException);
                    ejbErrors = true;
                }
            } catch (CryptoTokenOfflineException | InvalidWorkerIdException e) {
                item.setErrorMessage(e.getMessage());
                LOG.error("Error generating key", e);
                ejbErrors = true;
            }

            if (newAlias != null) {
                LOG.debug("Created key " + newAlias + " for signer " + getId());                  
                it.remove();     
                validRowFound = true;
            }
        }
        
        if (rowWithNoData != null && !rowWithNotAllData && !validRowFound && !ejbErrors) {
            showErrorForNoDataRow = true;
            rowWithNoData.setErrorMessage(errorMessage);
        }
        if (rowWithNoData != null && !showErrorForNoDataRow && rowWithNoData.getErrorMessage() != null) {
            rowWithNoData.setErrorMessage(null);
        }
        
        showErrors = rowWithNotAllData || showErrorForNoDataRow || ejbErrors;        
        // Error should be shown if all fields are not provided for any of the record rows 
        return !showErrors ? "worker-cryptotoken?faces-redirect=true&amp;includeViewParams=true&amp;id=" + getId() : null;
    }
    
    private int getNoOfEmptyFields(Item item) {
        int count = 0;
        if (isEmpty(item.getAlias())) {
            count = count + 1;
        }
        if (isEmpty(item.getKeyAlg())) {
            count = count + 1;
        }
        if (isEmpty(item.getKeySpec())) {
            count = count + 1;
        }
        return count;
    }

    public static class Item {

        private String alias;
        private String keyAlg;
        private String keySpec;
        private boolean first;
        private boolean last = true;
        private boolean selectAlgFromList = true;
        private boolean selectKeySpecFromList = true;
        private String errorMessage;
        private List<SelectItem> algMenuValues;
        private List<SelectItem> keySpecMenuValues;
        private String keysToBeGenerated = "1";

        public Item(WorkerConfig config) {
            this.keyAlg = config.getProperty("KEYALG");
            this.keySpec = config.getProperty("KEYSPEC");

            if (keyAlg == null) {
                /* if KEYALG is not set, fallback to RSA as that is first in
                 * the dropdown menu
                 */
                keyAlg = "RSA";
            }
        }

        public String getAlias() {
            return alias;
        }

        public void setAlias(String alias) {
            this.alias = StringUtils.trim(alias);
        }

        public String getKeyAlg() {
            return keyAlg;
        }

        public void setKeyAlg(String keyAlg) {
            final String newKeyAlg = StringUtils.trim(keyAlg);

            if (!this.keyAlg.equals(newKeyAlg)) {
                // invalidate keyspec menu values
                keySpecMenuValues = null;
                this.keyAlg = newKeyAlg;
            }
        }

        public String getKeySpec() {
            return keySpec;
        }

        public void setKeySpec(String keySpec) {
            this.keySpec = StringUtils.trim(keySpec);
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

        public boolean isSelectAlgFromList() {
            return selectAlgFromList;
        }

        public void setSelectAlgFromList(boolean selectAlgFromList) {
            this.selectAlgFromList = selectAlgFromList;
        }

        public boolean isSelectKeySpecFromList() {
            return selectKeySpecFromList;
        }

        public void setSelectKeySpecFromList(boolean selectKeyspecFromList) {
            this.selectKeySpecFromList = selectKeyspecFromList;
        }

        public List<SelectItem> getAlgorithmValues() {
            if (algMenuValues == null) {
                algMenuValues = KeyUtils.getAlgorithmsMap();
            }

            return algMenuValues;
        }

        public List<SelectItem> getKeySpecValues() {
            if (keySpecMenuValues == null) {
                keySpecMenuValues = KeyUtils.getKeySpecsMap(keyAlg);
            }

            return keySpecMenuValues;
        }

        public String getKeysToBeGenerated() {
            return keysToBeGenerated;
        }

        public void setKeysToBeGenerated(String keysToBeGenerated) {
            this.keysToBeGenerated = keysToBeGenerated;
        }
    }
}