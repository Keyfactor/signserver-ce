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
package org.signserver.groupkeyservice.server;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.KeyPair;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.groupkeyservice.common.FetchKeyRequest;
import org.signserver.groupkeyservice.common.FetchKeyResponse;
import org.signserver.groupkeyservice.common.GroupKeyServiceConstants;
import org.signserver.groupkeyservice.common.GroupKeyServiceStatus;
import org.signserver.groupkeyservice.common.IRemoveGroupKeyRequest;
import org.signserver.groupkeyservice.common.PregenerateKeysRequest;
import org.signserver.groupkeyservice.common.PregenerateKeysResponse;
import org.signserver.groupkeyservice.common.RemoveGroupKeyResponse;
import org.signserver.groupkeyservice.common.SwitchEncKeyRequest;
import org.signserver.groupkeyservice.common.SwitchEncKeyResponse;
import org.signserver.groupkeyservice.entities.EncKeyDataBean;
import org.signserver.groupkeyservice.entities.GroupKeyDataBean;
import org.signserver.groupkeyservice.entities.GroupKeyDataService;
import org.signserver.server.cryptotokens.IExtendedCryptoToken;

/**
 * Default Group Key Service implementing the basic functionality.
 * 
 * @author Philip Vendil 23 nov 2007
 * @version $Id$
 */
public class DefaultGroupKeyService extends BaseGroupKeyService {

    public transient Logger log = Logger.getLogger(this.getClass());
    
    private GroupKeyDataService gkds;

    @Override
    public void init(int workerId, WorkerConfig config, EntityManager em, IExtendedCryptoToken ect) {
        super.init(workerId, config, em, ect);
        
        
        
    }

    
    
    /**
     * @see org.signserver.groupkeyservice.server.IGroupKeyService#fetchGroupKey(org.signserver.groupkeyservice.common.FetchKeyRequest)
     */
    public FetchKeyResponse fetchGroupKey(FetchKeyRequest fetchKeyRequest)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {

        GroupKeyDataBean gkey = getGroupKeyDataService().fetchKey(fetchKeyRequest.getDocumentId(), fetchKeyRequest.isGenKeyIfNotExist());

        return new FetchKeyResponse(fetchKeyRequest.getDocumentId(), getKeyPart(fetchKeyRequest.getKeyPart(), gkey.getDecryptedData()));
    }

    /**
     * Help method returning the byte[] encoding of the key part the fetcher
     * is interested of.
     * 
     * @param keyPart one of GroupKeyServiceConstants.KEYPART_ constants.
     * @param decryptedData Object serialized key data
     * @return byte encoded key data of the part the fetcher requested
     */
    private byte[] getKeyPart(int keyPart, byte[] decryptedData) throws IllegalRequestException, SignServerException {
        byte[] retval = null;
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decryptedData));
            Object obj = ois.readObject();
            if (keyPart == GroupKeyServiceConstants.KEYPART_SYMMETRIC) {
                if (obj instanceof SecretKey) {
                    retval = ((SecretKey) obj).getEncoded();
                } else {
                    throw new IllegalRequestException("Error unsupported keypart, service only supports assymmetric keys but a request for a symmetric key was given");
                }
            } else {
                // Assymmetric key
                if (obj instanceof KeyPair) {
                    if (keyPart == GroupKeyServiceConstants.KEYPART_PRIVATE) {
                        retval = ((KeyPair) obj).getPrivate().getEncoded();
                    } else if (keyPart == GroupKeyServiceConstants.KEYPART_PUBLIC) {
                        retval = ((KeyPair) obj).getPublic().getEncoded();
                    } else {
                        throw new IllegalRequestException("Error unsupported keypart : " + keyPart);
                    }
                } else {
                    throw new IllegalRequestException("Error unsupported keypart, service only supports symmetric keys but a request for a assymmetric key part was given");
                }
            }
        } catch (IOException e) {
            log.error("Error, unexpected problems during object deserialization : " + e.getMessage(), e);
            throw new SignServerException("Error, unexpected problems during object deserialization : " + e.getMessage(), e);
        } catch (ClassNotFoundException e) {
            log.error("Error, unexpected problems during object deserialization : " + e.getMessage(), e);
            throw new SignServerException("Error, unexpected problems during object deserialization : " + e.getMessage(), e);
        }
        return retval;
    }

    /**
     * @see org.signserver.groupkeyservice.server.IGroupKeyService#pregenerateGroupKeys(org.signserver.groupkeyservice.common.PregenerateKeysRequest)
     */
    public PregenerateKeysResponse pregenerateGroupKeys(
            PregenerateKeysRequest pregenerateKeysRequest)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {

        int keysGenerated = 0;
        for (; keysGenerated < pregenerateKeysRequest.getNumberOfKeys(); keysGenerated++) {
            try {
                getGroupKeyDataService().pregenerateKey();
            } catch (SignServerException e) {
                log.error("General error when pregenerating a key", e);
            }
        }
        return new PregenerateKeysResponse(keysGenerated);
    }

    /**
     * @see org.signserver.groupkeyservice.server.IGroupKeyService#removeGroupKeys(org.signserver.groupkeyservice.common.IRemoveGroupKeyRequest)
     */
    public RemoveGroupKeyResponse removeGroupKeys(
            IRemoveGroupKeyRequest removeGroupKeyRequests)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {
        return getGroupKeyDataService().removeKeys(removeGroupKeyRequests);
    }

    /**
     * @see org.signserver.groupkeyservice.server.IGroupKeyService#switchEncryptionKey(org.signserver.groupkeyservice.common.SwitchEncKeyRequest)
     */
    public SwitchEncKeyResponse switchEncryptionKey(
            SwitchEncKeyRequest switchEncKeyRequest)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {

        return new SwitchEncKeyResponse(getGroupKeyDataService().switchEncKey());
    }

    protected GroupKeyDataService getGroupKeyDataService() {
        if (gkds == null) {
            gkds = new GroupKeyDataService(workerId, em, this.config.getProperties(), ect);
        }
        return gkds;
    }

    /**
     * @see org.signserver.groupkeyservice.server.IGroupKeyService#getStatus()
     */
    public WorkerStatus getStatus() {
        long numOfKeys = getGroupKeyDataService().getNumOfKeys(new Date(0), new Date());
        long numAssignedKeys = getGroupKeyDataService().getNumOfAssignedKeys(new Date(0), new Date());
        long numUnassignedKeys = getGroupKeyDataService().getNumOfUnassignedKeys(new Date(0), new Date());
        EncKeyDataBean currentEncKey = getGroupKeyDataService().getCurrentEncKeyRef();
        if (currentEncKey == null) {
            return new GroupKeyServiceStatus(workerId, ect.getCryptoTokenStatus(), config, numUnassignedKeys, numOfKeys, numAssignedKeys, null, 0, null);
        }
        return new GroupKeyServiceStatus(workerId, ect.getCryptoTokenStatus(), config, numUnassignedKeys, numOfKeys, numAssignedKeys, currentEncKey.getEncKeyRef(), currentEncKey.getNumberOfEncryptions(), currentEncKey.getUsageStarted());
    }
}
