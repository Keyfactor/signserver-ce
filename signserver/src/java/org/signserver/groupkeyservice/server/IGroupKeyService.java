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

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.groupkeyservice.common.FetchKeyRequest;
import org.signserver.groupkeyservice.common.FetchKeyResponse;
import org.signserver.groupkeyservice.common.IRemoveGroupKeyRequest;
import org.signserver.groupkeyservice.common.PregenerateKeysRequest;
import org.signserver.groupkeyservice.common.PregenerateKeysResponse;
import org.signserver.groupkeyservice.common.RemoveGroupKeyResponse;
import org.signserver.groupkeyservice.common.SwitchEncKeyRequest;
import org.signserver.groupkeyservice.common.SwitchEncKeyResponse;
import org.signserver.server.cryptotokens.IExtendedCryptoToken;

/**
 * Interface all GroupKeyServices have to implement.
 * 
 * It's recommended that all implementing classes instead inherits
 * the BaseGroupKeyService.
 * 
 * It have four main methods
 *  fetchGroupKey            : Main method used to decrypt and fetch a key.
 *  pregenerateGroupKeys     : Used to generate unassigned keys. (optional)
 *  switchEncryptionKey      : Tells the service it's time to switch the key used for encryption. (Optional)
 *  removeGroupKeys          : Removes old keys (optional)
 *  
 * 
 * @author Philip Vendil 13 nov 2007
 *
 * @version $Id$
 */

public interface IGroupKeyService {
	
	/**
	 * Initialization method that should be called directly after creation.
	 * @param workerId the unique id of the worker
	 * @param config the configuration stored in database
	 * @param em reference to the entity manager
	 * @param ect the extended crypto token used by the group key service.
	 */
	public void init(int workerId, WorkerConfig config, EntityManager em, IExtendedCryptoToken ect);
	
	
	/**
	 * Main method of a Group Key Service responsible for fetching keys from
	 * the database.
	 * 
	 * @param fetchKeyRequest
	 * @return a FetchKeyReponse
	 * @throws IllegalRequestException if data in the request didn't conform with the specification.
	 * @throws CryptoTokenOfflineException if the crypto token isn't online. 
	 * @throws SignServerException for general failure exception during key generation.
	 * @see org.signserver.groupkeyservice.common.FetchKeyRequest
	 * @see org.signserver.groupkeyservice.common.FetchKeyResponse
	 */
	FetchKeyResponse fetchGroupKey(FetchKeyRequest fetchKeyRequest) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException;

	/**
	 * Method that instructs the group key service to pregenerate keys. 
	 * This method is called at periods when the server is having
	 * a low load. This option is optional to implement, if the
	 * service doesn't support this method it should return null.
	 * 
	 * 
	 * @param pregenerateKeysRequest request data
	 * @return a response containing number of keys generated, etc
	 * @throws IllegalRequestException if requests contain unsupported data.
	 * @throws CryptoTokenOfflineException if the crypto token isn't online.
	 * @throws SignServerException for general failure exception during key generation.
	 * @see org.signserver.groupkeyservice.common.PregenerateKeysRequest
	 * @see org.signserver.groupkeyservice.common.PregenerateKeysResponse
	 */
	PregenerateKeysResponse pregenerateGroupKeys(PregenerateKeysRequest pregenerateKeysRequest) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException;

	
	/**
	 * Method instructing the key service to switch the encryption key for
	 * storing the group keys in the database. This to ensure that one encryption
	 * key isn't exposed through to much data.
	 * 
	 * This method is optional for the implementing service to implement, if
	 * it's not implemented it should return null.
	 * 
	 * @param switchEncKeyRequest request data.
	 * @return a response containing the result of the operation such as new key index.
	 * @throws IllegalRequestException if requests contain unsupported data.
	 * @throws CryptoTokenOfflineException if the crypto token isn't online.
	 * @throws SignServerException  for general failure exception during key generation.
	 * @see org.signserver.groupkeyservice.common.SwitchEncKeyRequest
	 * @see org.signserver.groupkeyservice.common.SwitchEncKeyResponse
	 */
	SwitchEncKeyResponse switchEncryptionKey(SwitchEncKeyRequest switchEncKeyRequest) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException;
	
	/**
	 * Method instructing the key service to remove old group keys not used anymore
	 * it up to the caller to check that the implementing service supports the type
	 * of IRemoveGroupKeyRequest used. The request should contain data specifying which
	 * keys that should be removed.
	 * 
	 * This method is optional for the implementing service to implement, if
	 * it's not implemented it should return null.
	 * 
	 * @param removeGroupKeyRequests request data.
	 * @return a response containing the result of the operation such as number of keys actually removed.
	 * @throws IllegalRequestException if requests contain unsupported data.
	 * @throws CryptoTokenOfflineException if the crypto token isn't online.
	 * @throws SignServerException  for general failure exception during key generation.
	 * @see org.signserver.groupkeyservice.common.RemoveGroupKeyResponse
	 * @see org.signserver.groupkeyservice.common.IRemoveGroupKeyRequest
	 */
	RemoveGroupKeyResponse removeGroupKeys(IRemoveGroupKeyRequest removeGroupKeyRequests) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException;
	

	/**
	 * Should return the actual status of the worker, status could be if
	 * the signer is activated or not, or equivalent for a service.
	 * @return a WorkerStatus object.
	 */
	public WorkerStatus getStatus();
}
