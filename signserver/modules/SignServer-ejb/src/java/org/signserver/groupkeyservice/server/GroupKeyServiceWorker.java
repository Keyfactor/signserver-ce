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

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.groupkeyservice.common.FetchKeyRequest;
import org.signserver.groupkeyservice.common.GroupKeyServiceConstants;
import org.signserver.groupkeyservice.common.IRemoveGroupKeyRequest;
import org.signserver.groupkeyservice.common.PregenerateKeysRequest;
import org.signserver.groupkeyservice.common.SwitchEncKeyRequest;
import org.signserver.server.BaseProcessable;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.IExtendedCryptoToken;

/**
 * Class acting as middle-ware transforming an ISigner to
 * a IGroupKeyService.
 *
 * @author Philip Vendil 16 nov 2007
 * @version $Id$
 */
public class GroupKeyServiceWorker extends BaseProcessable {

    private transient Logger log = Logger.getLogger(this.getClass());
    
    private IGroupKeyService groupKeyService;

    /**
     * Initialization method creating the group key service
     * @see org.signserver.server.BaseWorker#init(int, org.signserver.common.WorkerConfig, javax.persistence.EntityManager)
     */
    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEntityManager) {
        super.init(workerId, config, workerContext, workerEntityManager);

        groupKeyService = createGroupService(config);
    }

    /**
     * Creating a group key service depending on the TYPE setting
     * @param config configuration containing the group key service to create
     * @return a non initialized group key service.
     */
    private IGroupKeyService createGroupService(WorkerConfig config) {
        String classPath = config.getProperties().getProperty(GroupKeyServiceConstants.GROUPKEYDATASERVICE_TYPE, GroupKeyServiceConstants.DEFAULT_TYPE);
        IGroupKeyService retval = null;
        try {
            if (classPath != null) {
                Class<?> implClass = Class.forName(classPath);
                retval = (IGroupKeyService) implClass.newInstance();


                retval.init(workerId, config, em, getExtendedCryptoToken());
            }
        } catch (ClassNotFoundException e) {
            log.error("Error instatiating Group Key Service, check that the TYPE setting of workerid : " + workerId + " have the correct class path.", e);
        } catch (IllegalAccessException e) {
            log.error("Error instatiating Group Key Service, check that the TYPE setting of workerid : " + workerId + " have the correct class path.", e);
        } catch (InstantiationException e) {
            log.error("Error instatiating Group Key Service, check that the TYPE setting of workerid : " + workerId + " have the correct class path.", e);
        }

        return retval;
    }

    private IExtendedCryptoToken getExtendedCryptoToken() {
        if (!(getCryptoToken() instanceof IExtendedCryptoToken)) {
            log.error("Error the crypto token associated with the Group Key Service " + workerId + " isn't an extended crypto token.");
        }
        return (IExtendedCryptoToken) getCryptoToken();
    }

    /**
     * Main method of the container calling the appropriate method
     * of the GroupKeyService depending on the type of request.
     * 
     * @see org.signserver.server.signers.IProcessable#processData(org.signserver.common.ProcessRequest, java.security.cert.X509Certificate)
     */
    public ProcessResponse processData(ProcessRequest processRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {

        if (processRequest instanceof FetchKeyRequest) {
            return groupKeyService.fetchGroupKey((FetchKeyRequest) processRequest);
        }

        if (processRequest instanceof PregenerateKeysRequest) {
            return groupKeyService.pregenerateGroupKeys((PregenerateKeysRequest) processRequest);
        }

        if (processRequest instanceof SwitchEncKeyRequest) {
            return groupKeyService.switchEncryptionKey((SwitchEncKeyRequest) processRequest);
        }

        if (processRequest instanceof IRemoveGroupKeyRequest) {
            return groupKeyService.removeGroupKeys((IRemoveGroupKeyRequest) processRequest);
        }

        throw new IllegalRequestException("The process request sent to group key service with id " + workerId + " isn't supported");
    }

    /**
     * @see org.signserver.server.signers.BaseProcessable#getStatus()
     */
    public WorkerStatus getStatus() {
        return groupKeyService.getStatus();
    }
}
