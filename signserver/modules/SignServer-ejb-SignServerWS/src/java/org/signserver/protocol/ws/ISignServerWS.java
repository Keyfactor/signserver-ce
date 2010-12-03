package org.signserver.protocol.ws;

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


import java.util.Collection;

import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.SignServerException;

/**
 * Interface towards SignServer Web Service clients.
 * 
 * Contains the following methods:
 * 
 * signData  : Base method performing signatures
 * getStatus : Method returning the status of a given signerId
 * 
 * @author Philip Vendil 28 okt 2007
 *
 * @version $Id: ISignServerWS.java 500 2009-04-22 12:10:07Z anatom $
 */
public interface ISignServerWS {
	
	public static final String ALLWORKERS = "ALLWORKERS";
	
	/**
	 * Method used to return the status of a worker at the sign server.
	 * 
	 * @param workerIdOrName id or name of the worker that should report it's status or 0 for all workers.
	 * @return returns the status of the given workerID or name, "ALLWORKERS" will return all workers.
	 * available workers will report.
	 * @throws InvalidWorkerIdException if the given worker id  doesn't exist.
	 */
	public Collection<WorkerStatusWS> getStatus(String workerIdOrName) throws InvalidWorkerIdException;
	
  /**
   * 
   * @param workerIdOrName id or name of the worker that should report it's status or 0 for all workers.
   * @param requests collection of sign requests to process 
   * @return a collection of corresponding responses.
   * @throws InvalidWorkerIdException if the name of id couldn't be found.
   * @throws IllegalRequestException if the request isn't correct.
   * @throws CryptoTokenOfflineException if the signing token isn't online.
   * @throws SignServerException if some other error occurred server side during process.
   */
    public Collection<ProcessResponseWS> process(String workerIdOrName, Collection<ProcessRequestWS> requests) 
      throws InvalidWorkerIdException ,IllegalRequestException, CryptoTokenOfflineException, SignServerException;
}
