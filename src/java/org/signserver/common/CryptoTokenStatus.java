/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.signserver.common;


/**
 * Abstract Status class containing token status.
 * 
 * 
 * @author Philip Vendil 23 nov 2007
 *
 * @version $Id: CryptoTokenStatus.java,v 1.1 2007-11-27 06:05:06 herrvendil Exp $
 */

public abstract class CryptoTokenStatus extends WorkerStatus{
	
	public static final int STATUS_ACTIVE  = 1;
	public static final int STATUS_OFFLINE = 2;
	
	private int tokenStatus = 0;
	/** 
	 * Main constructor
	 */
	public CryptoTokenStatus(int tokenStatus, WorkerConfig config){
		super(config);
		this.tokenStatus = tokenStatus;
	}
	
	/**
	 * @return Returns the tokenStatus.
	 */
	public int getTokenStatus() {
		return tokenStatus;
	}
}
