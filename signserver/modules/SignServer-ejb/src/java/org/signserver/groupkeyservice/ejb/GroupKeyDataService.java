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
package org.signserver.groupkeyservice.ejb;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import javax.persistence.EntityManager;
import javax.persistence.Query;

import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.groupkeyservice.common.DocumentIDRemoveGroupKeyRequest;
import org.signserver.groupkeyservice.common.GroupKeyServiceConstants;
import org.signserver.groupkeyservice.common.IRemoveGroupKeyRequest;
import org.signserver.groupkeyservice.common.RemoveGroupKeyResponse;
import org.signserver.groupkeyservice.common.TimeRemoveGroupKeyRequest;
import org.signserver.server.cryptotokens.IExtendedCryptoToken;

/**
 * Service bean responsible for managing group keys, i.e making
 * sure the are encrypted with the right encryption key
 * and that the key is switch periodically.
 * 
 * @author Philip Vendil 19 nov 2007
 * @version $Id$
 */
public class GroupKeyDataService {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(GroupKeyDataService.class);
    
    EntityManager em;
    Properties props;
    int workerId;
    IExtendedCryptoToken ehct;
    
    /**
     * Method fetching the Key Switch Threshold from the properties
     * of using the default key switch property if it isn't set.
     */
    private long keySwitchThreshold;
    
    private String groupKeyAlg;
    
    private String groupKeySpec;
    
    private String encKeySpec;
    
    private String encKeyAlg = null;
    
    private Boolean usePregeneration;

    public GroupKeyDataService(int workerId, EntityManager em, Properties props, IExtendedCryptoToken ehct) {
        this.em = em;
        this.props = props;
        this.workerId = workerId;
        this.ehct = ehct;
    }

    /**
     * Method to fetch and decrypt a key from database.
     * @param documentId the unique documentId associated with the key.
     * @param genKeyIfNotExist if a unassigned key should be set (or generated if pregeneration isn't used)
     * 
     * @return the GroupKeyDataBean associated with the documentId
     * @throws CryptoTokenOfflineException 
     * @throws IllegalRequestException 
     * @throws SignServerException 
     */
    public GroupKeyDataBean fetchKey(String documentId, boolean genKeyIfNotExist) throws CryptoTokenOfflineException, IllegalRequestException, SignServerException {
        GroupKeyDataBean retval = null;
        // Find Key
        Collection<?> groupKeyResult = em.createNamedQuery("GroupKeyDataBean.findByDocumentId").setParameter(1, this.workerId).setParameter(2, documentId).getResultList();

        if (groupKeyResult.size() > 0) {
            // GroupKey is  assigned return it.
            retval = (GroupKeyDataBean) groupKeyResult.iterator().next();
            retval.setDecryptedData(ehct.decryptData(retval.getEncKeyRef(), retval.getEncryptedData()));
            retval.setLastFetchedDate(new Date());
        } else {
            // No group key is assigned
            if (genKeyIfNotExist) {

                List<?> result = em.createNamedQuery("GroupKeyDataBean.findUnassignedKey").setParameter(1, this.workerId).setMaxResults(1).getResultList();

                if (!usePregeneration() || result.isEmpty()) {
                    // Generate new Key
                    retval = genNewGroupKeyData();
                    retval.setDocumentID(documentId);
                    retval.setFirstUsedDate(new Date());
                    retval.setLastFetchedDate(new Date());
                    retval.setDecryptedData(ehct.decryptData(retval.getEncKeyRef(), retval.getEncryptedData()));
                    em.persist(retval);
                } else {
                    // Assign existing key
                    retval = (GroupKeyDataBean) result.get(0);
                    retval.setDocumentID(documentId);
                    retval.setDecryptedData(ehct.decryptData(retval.getEncKeyRef(), retval.getEncryptedData()));
                    retval.setLastFetchedDate(new Date());
                    retval.setFirstUsedDate(new Date());
                }
            } else {
                throw new IllegalRequestException("No group key have been associated with the given document id  '" + documentId + "'.");
            }
        }
        return retval;
    }

    private GroupKeyDataBean genNewGroupKeyData() throws CryptoTokenOfflineException, SignServerException {
        // Generate Key
        Serializable key = null;
        String keyAlg = getGroupKeyAlg();
        String keySpec = getGroupKeySpec();
        try {
            key = ehct.genExportableKey(keyAlg, keySpec);
        } catch (IllegalRequestException e) {
            LOG.error(e);
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {

            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(key);
            oos.close();
        } catch (IOException e) {
            LOG.error(e);
            throw new SignServerException("IOException : " + e.getMessage(), e);
        }

        Collection<?> encKeyResult = em.createNamedQuery("EncKeyDataBean.findByUseFlag").setParameter(1, this.workerId).getResultList();

        String encKeyRef = null;
        if (encKeyResult.isEmpty()) {
            // Encryption key doesn't exist, create one.
            encKeyRef = switchEncKey(true, false);
        } else if (encKeyResult.size() == 1) {
            EncKeyDataBean ekdv = (EncKeyDataBean) encKeyResult.iterator().next();
            long numberOfEncryptions = ekdv.getNumberOfEncryptions();
            if (numberOfEncryptions >= getKeySwitchThreshold()) {
                ekdv.setInUse(false);
                ekdv.setUsageEnded(new Date());
                encKeyRef = switchEncKey(true, false);
            } else {
                encKeyRef = ekdv.getEncKeyRef();
                ekdv.setNumberOfEncryptions(ekdv.getNumberOfEncryptions() + 1);
            }
        } else {
            LOG.error("Error in encryption key table, same worker cannot have more than on key in use at the same time");
        }

        byte[] keyData = baos.toByteArray();

        GroupKeyDataBean gkd = new GroupKeyDataBean();
        gkd.setCreationDate(new Date());
        gkd.setWorkerId(workerId);
        gkd.setDecryptedData(keyData);
        gkd.setEncryptedData(ehct.encryptData(encKeyRef, keyData));
        gkd.setEncKeyRef(encKeyRef);

        return gkd;
    }

    public void pregenerateKey() throws CryptoTokenOfflineException, IllegalRequestException, SignServerException {
        if (!usePregeneration()) {
            throw new IllegalRequestException("Error: Group Key Service with id " + workerId + " doesn't support pregeneration");
        }
        GroupKeyDataBean keyData = genNewGroupKeyData();
        em.persist(keyData);
    }

    private String switchEncKey(boolean incrementCounter, boolean unsetPrevious) throws CryptoTokenOfflineException {
        if (unsetPrevious) {
            Collection<?> encKeyResult = em.createNamedQuery("EncKeyDataBean.findByUseFlag").setParameter(1, this.workerId).getResultList();
            Iterator<?> iter = encKeyResult.iterator();
            while (iter.hasNext()) {
                EncKeyDataBean next = (EncKeyDataBean) iter.next();
                next.setInUse(false);
                next.setUsageEnded(new Date());
            }
        }

        String keyRef = null;
        try {
            keyRef = ehct.genNonExportableKey(getEncKeyAlg(), getEncKeySpec());
            EncKeyDataBean ekdv = new EncKeyDataBean();
            ekdv.setEncKeyRef(keyRef);
            ekdv.setInUse(true);
            if (incrementCounter) {
                ekdv.setNumberOfEncryptions(1);
            } else {
                ekdv.setNumberOfEncryptions(0);
            }
            ekdv.setUsageStarted(new Date());
            ekdv.setWorkerId(workerId);
            em.persist(ekdv);
        } catch (IllegalRequestException e) {
            LOG.error("Error, Group Key Service " + workerId + " missconfigured, check key encryption algorithm settings");
        }
        return keyRef;
    }

    public String switchEncKey() throws CryptoTokenOfflineException {
        return switchEncKey(false, true);
    }

    public RemoveGroupKeyResponse removeKeys(IRemoveGroupKeyRequest request) throws IllegalRequestException {
        RemoveGroupKeyResponse retval = null;
        if (request instanceof DocumentIDRemoveGroupKeyRequest) {
            long deleted = 0;
            for (String documentId : ((DocumentIDRemoveGroupKeyRequest) request).getDocumentIds()) {
                Collection<?> groupKeyResult = em.createNamedQuery("GroupKeyDataBean.findByDocumentId").setParameter(1, this.workerId).setParameter(2, documentId).getResultList();

                for (Object element : groupKeyResult) {
                    GroupKeyDataBean next = (GroupKeyDataBean) element;
                    em.remove(next);
                    deleted++;
                }
            }
            retval = new RemoveGroupKeyResponse(true, deleted);
        } else if (request instanceof TimeRemoveGroupKeyRequest) {
            try {
                TimeRemoveGroupKeyRequest timeReq = (TimeRemoveGroupKeyRequest) request;
                Query q = null;
                if (timeReq.getType() == TimeRemoveGroupKeyRequest.TYPE_CREATIONDATE) {
                    q = em.createQuery("DELETE FROM GroupKeyDataBean a WHERE a.workerId = :workerId AND a.creationDate >= :beginDate AND a.creationDate <= :endDate");
                } else if (timeReq.getType() == TimeRemoveGroupKeyRequest.TYPE_FIRSTUSEDDATE) {
                    q = em.createQuery("DELETE FROM GroupKeyDataBean a WHERE a.workerId = :workerId AND a.firstUsedDate >= :beginDate AND a.firstUsedDate <= :endDate");
                } else if (timeReq.getType() == TimeRemoveGroupKeyRequest.TYPE_LASTFETCHEDDATE) {
                    q = em.createQuery("DELETE FROM GroupKeyDataBean a WHERE a.workerId = :workerId AND a.lastFetchedDate >= :beginDate AND a.lastFetchedDate <= :endDate");
                } else {
                    throw new IllegalRequestException("Unsupported type " + timeReq.getType() + " in TimeRemoveGroupKeyRequest");
                }
                q.setParameter("workerId", this.workerId);
                q.setParameter("beginDate", timeReq.getBeginDate());
                q.setParameter("endDate", timeReq.getEndDate());
                int deleted = q.executeUpdate();
                retval = new RemoveGroupKeyResponse(true, deleted);
            } catch (RuntimeException e) {
                LOG.error(e, e);
                retval = new RemoveGroupKeyResponse(false, 0);
            }
        } else {
            throw new IllegalRequestException("Unsupported request type " + request.getClass().getName() + " when removing keys.");
        }
        return retval;
    }

    public long getNumOfUnassignedKeys(Date startDate, Date endDate) {
        Number result = (Number) em.createNamedQuery("GroupKeyDataBean.numberOfUnassignedKeys").setParameter(1, this.workerId).setParameter(2, startDate).setParameter(3, endDate).getSingleResult();
        return result.longValue();
    }

    public long getNumOfAssignedKeys(Date startDate, Date endDate) {
        Number result = (Number) em.createNamedQuery("GroupKeyDataBean.numberOfAssignedKeys").setParameter(1, this.workerId).setParameter(2, startDate).setParameter(3, endDate).getSingleResult();
        return result.longValue();
    }

    public long getNumOfKeys(Date startDate, Date endDate) {
        Number result = (Number) em.createNamedQuery("GroupKeyDataBean.totalNumberOfKeys").setParameter(1, this.workerId).setParameter(2, startDate).setParameter(3, endDate).getSingleResult();
        return result.longValue();
    }

    /**
     * Method returning data about the currently used encryption key
     * @return null if no encryption key have been initialized.
     */
    public EncKeyDataBean getCurrentEncKeyRef() {
        EncKeyDataBean retval = null;

        Collection<?> encKeyResult = em.createNamedQuery("EncKeyDataBean.findByUseFlag").setParameter(1, this.workerId).getResultList();

        if (encKeyResult.size() > 0) {
            retval = (EncKeyDataBean) encKeyResult.iterator().next();
        }
        return retval;
    }

    private long getKeySwitchThreshold() {
        if (keySwitchThreshold == 0) {
            if (props.getProperty(GroupKeyServiceConstants.GROUPKEYDATASERVICE_KEYSWITCHTHRESHOLD) != null) {
                try {
                    keySwitchThreshold = Long.parseLong(props.getProperty(GroupKeyServiceConstants.GROUPKEYDATASERVICE_KEYSWITCHTHRESHOLD));
                } catch (NumberFormatException e) {
                    LOG.error("Error in Group Key Service configuration with workerId " + workerId
                            + ", setting " + GroupKeyServiceConstants.GROUPKEYDATASERVICE_KEYSWITCHTHRESHOLD + " should only contain numbers. Using default value");
                }
            }
            if (keySwitchThreshold == 0) {
                keySwitchThreshold = GroupKeyServiceConstants.DEFAULT_KEYSWITCHTHRESHOLD;
            }

        }
        return keySwitchThreshold;
    }

    private String getGroupKeyAlg() {
        if (groupKeyAlg == null) {
            groupKeyAlg = props.getProperty(GroupKeyServiceConstants.GROUPKEYDATASERVICE_GROUPKEYALG, GroupKeyServiceConstants.DEFAULT_GROUPKEYALG);
        }
        return groupKeyAlg;
    }

    private String getGroupKeySpec() {
        if (groupKeySpec == null) {
            groupKeySpec = props.getProperty(GroupKeyServiceConstants.GROUPKEYDATASERVICE_GROUPKEYSPEC, GroupKeyServiceConstants.DEFAULT_GROUPKEYSPEC);
        }
        return groupKeySpec;
    }

    private String getEncKeyAlg() {
        if (encKeyAlg == null) {
            encKeyAlg = props.getProperty(GroupKeyServiceConstants.GROUPKEYDATASERVICE_ENCKEYALG, GroupKeyServiceConstants.DEFAULT_ENCKEYALG);
        }
        return encKeyAlg;
    }

    private String getEncKeySpec() {
        if (encKeySpec == null) {
            encKeySpec = props.getProperty(GroupKeyServiceConstants.GROUPKEYDATASERVICE_ENCKEYSPEC, GroupKeyServiceConstants.DEFAULT_ENCKEYSPEC);
        }
        return encKeySpec;
    }

    private boolean usePregeneration() {
        if (usePregeneration == null) {
            String value = props.getProperty(GroupKeyServiceConstants.GROUPKEYDATASERVICE_USEPREGENERATION, GroupKeyServiceConstants.DEFAULT_USEPREGENERATION);
            if (!value.equalsIgnoreCase("TRUE") && !value.equalsIgnoreCase("FALSE")) {
                LOG.error("Error in Group Key Service configuration with workerId " + workerId
                        + ", setting " + GroupKeyServiceConstants.GROUPKEYDATASERVICE_USEPREGENERATION + " should be either TRUE or FALSE. Using default value.");
                value = GroupKeyServiceConstants.DEFAULT_USEPREGENERATION;
            }
            usePregeneration = Boolean.parseBoolean(value);
        }
        return usePregeneration.booleanValue();
    }
}
