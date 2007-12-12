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

package org.signserver.server.signers;

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.SignerStatus;
import org.signserver.common.WorkerStatus;
import org.signserver.server.BaseProcessable;

/**
 * 
 * Base class that all signers can extend to cover basic in common functionality
 * 
 * @author Philip Vendil
 *
 * $Id: BaseSigner.java,v 1.7 2007-12-12 14:00:06 herrvendil Exp $
 */
public abstract class BaseSigner extends BaseProcessable implements ISigner {
	

	/**
	 * @see org.signserver.server.signers.IProcessable#getStatus()
	 */
	public WorkerStatus getStatus() {
		SignerStatus retval = null;
		
        try {
			retval = new SignerStatus(workerId, getCryptoToken().getCryptoTokenStatus(), new ProcessableConfig( config), getSigningCertificate());
		} catch (CryptoTokenOfflineException e) {
			retval = new SignerStatus(workerId, getCryptoToken().getCryptoTokenStatus(), new ProcessableConfig( config), null);
		}
		
		
		return retval;
	}
	
}
