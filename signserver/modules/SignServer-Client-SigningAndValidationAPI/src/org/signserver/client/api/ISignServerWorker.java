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
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;

/**
 * Interface for requesting a worker to process something.
 * 
 * @author Markus Kilås
 * @version $Id: ISignServerWorker.java -1   $
 */
public interface ISignServerWorker {
	
	/**
	 * Send a request to a specified worker.
	 * 
	 * @param workerIdOrName Id or name of worker which should process the request.
	 * @param request The request.
	 * @param context The context.
	 * @return The response from the worker.
	 * @throws CryptoTokenOfflineException If the signers token isn't activated. 
	 * @throws IllegalRequestException If illegal request is sent to the method.
	 * @throws SignServerException If some other error occurred server side during process.
	 */
	public ProcessResponse process(String workerIdOrName, ProcessRequest request, RequestContext context) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException;
	
}
