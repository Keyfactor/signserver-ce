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
 * @version $Id: ISigningAndValidation.java -1   $
 */
public interface ISigningAndValidation extends ISignServerWorker {
	
	/**
	 * Request a particular document to be signed by a given signer. 
	 * <p>
	 * The encoding of the document field depends on the signer. For instance 
	 * the XMLSigner expects the document to be the content of a XML file.
	 * 
	 * @param signerIdOrName The ID or name of the signer to perform the signing.
	 * @param document The document to be signed.  
	 * @return  A GenericSignResponse containing the signed document.
	 * @throws IllegalRequestException If an illegal request is sent to the method 
	 * 			(such as specifying a non-existing worker-id etc).
	 * @throws CryptoTokenOfflineException If the signers token isn't activated.
	 * @throws SignServerException If some other error occurred on the server side during process.
	 */
	public GenericSignResponse sign(String signerIdOrName, byte[] document) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException;
	
	/**
	 * Request a particular document to be validated by a given (document) validator.
	 * <p>
	 * The encoding of the document field depends on the validator. For instance 
	 * the XMLValidator expects the document to be the content of a XML file.
	 * <p>
	 * Note: Depending on the underlying implementation this method might throw
	 *  exceptions when a document (or a certificate in a document) is invalid 
	 *  instead of setting the Status field in the response.
	 * <p>
	 * The {@link GenericValidationResponse#isValid()} method can be used to see 
	 * if the document was found valid.  
	 * 
	 * @param validatorIdOrName The ID or name of the validator to perform the validation.
	 * @param document The document to be signed.
	 * @return A GenericValidationResponse containing the status of the validation.
	 * @throws IllegalRequestException If an illegal request is sent to the method 
	 * 			(such as specifying a non-existing worker-id etc).
	 * @throws CryptoTokenOfflineException
	 * @throws SignServerException If some other error occurred on the server side during process.
	 */
	public GenericValidationResponse validate(String validatorIdOrName, byte[] document) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException;
}
