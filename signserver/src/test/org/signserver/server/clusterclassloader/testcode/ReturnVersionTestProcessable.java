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

package org.signserver.server.clusterclassloader.testcode;

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.SignerStatus;
import org.signserver.common.WorkerStatus;
import org.signserver.server.BaseProcessable;

/**
 * 
 * Class used when testing the ClusterClassLoader 
 * 
 * @author Philip Vendil 7 jun 2008
 *
 * @version $Id$
 */

public class ReturnVersionTestProcessable extends BaseProcessable {

	/* (non-Javadoc)
	 * @see org.signserver.server.IProcessable#processData(org.signserver.common.ProcessRequest, org.signserver.common.RequestContext)
	 */
	public ProcessResponse processData(ProcessRequest signRequest,
			RequestContext requestContext) throws IllegalRequestException,
			CryptoTokenOfflineException, SignServerException {
		GenericSignRequest req = (GenericSignRequest) signRequest;
		String data = new String(req.getRequestData());
		
		@SuppressWarnings("unused")
		SomeClass c = new SomeClass();
		
		return new GenericSignResponse(req.getRequestID(),(data + ", classname + " + this.getClass().getName()).getBytes(),null,null,null);
	}

	/* (non-Javadoc)
	 * @see org.signserver.server.IWorker#getStatus()
	 */
	public WorkerStatus getStatus() {
		return  new SignerStatus(workerId,  SignerStatus.STATUS_ACTIVE, new ProcessableConfig( config), null);
	}

}
