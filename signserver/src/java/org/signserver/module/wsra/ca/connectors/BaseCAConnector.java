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
 
package org.signserver.module.wsra.ca.connectors;

import java.util.Properties;

import org.signserver.common.SignServerException;
import org.signserver.server.cryptotokens.ICryptoToken;

/**
 * Abstract base class of a CAConnector containing initialization
 * and help methods common for most types of CA connectors.
 * 
 * 
 * @author Philip Vendil 19 okt 2008
 *
 * @version $Id$
 */

public abstract class BaseCAConnector implements ICAConnector {

	protected int workerId;
	protected int connectorId;
	protected Properties props;
	protected ICryptoToken cryptoToken;

	/**
	 * Base init method taking care of initializing the protected
	 * fields.
	 * 
	 * @see org.signserver.module.wsra.ca.connectors.ICAConnector#init(int, int, java.util.Properties, org.signserver.server.cryptotokens.ICryptoToken)
	 */	
	public void init(int workerId, int connectorId, Properties props,
			ICryptoToken ct) throws SignServerException {
		this.workerId = workerId;
		this.connectorId = connectorId;
		this.props = props;
		this.cryptoToken = ct;
	}


}
