package org.signserver.client.api;

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GenericValidationResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;

/**
 * Interface for requesting signing or validation of documents from SignServer.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public interface ISigningAndValidation {
	
	public GenericSignResponse sign(String signerIdOrName, byte[] document) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException;
	
	public GenericValidationResponse validate(String validatorIdOrName, byte[] document) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException;
}
