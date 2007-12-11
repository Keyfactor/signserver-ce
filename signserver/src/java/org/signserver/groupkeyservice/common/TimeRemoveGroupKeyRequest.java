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
package org.signserver.groupkeyservice.common;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Date;

import org.signserver.common.RequestAndResponseManager;

/**
 * Class containing info about the remove group keys request
 * with time based specification.
 * 
 * 
 * @author Philip Vendil 13 nov 2007
 *
 * @version $Id: TimeRemoveGroupKeyRequest.java,v 1.2 2007-12-11 05:36:58 herrvendil Exp $
 */
public class TimeRemoveGroupKeyRequest implements IRemoveGroupKeyRequest {

	private static final long serialVersionUID = 1L;
	
	public static final int TYPE_CREATIONDATE = 0;
	public static final int TYPE_FIRSTUSEDDATE = 1;
	public static final int TYPE_LASTFETCHEDDATE = 2;
	
	private int type;
	private Date beginDate;
	private Date endDate;
	
    /**
     * Default constructor used during serialization
     */
	public TimeRemoveGroupKeyRequest(){}
	
	/**
	 * 
	 * @param type one of the TYPE_constants 
	 * @param beginDate the start date in the interval to remove.
	 * @param endDate the end date in the interval to remove.
	 */
	public TimeRemoveGroupKeyRequest(int type, Date beginDate, Date endDate) {
		super();
		this.type = type;
		this.beginDate = beginDate;
		this.endDate = endDate;
	}

	/**
	 * 
	 * @return one of the TYPE_constants 
	 */
	public int getType() {
		return type;
	}

	/**
	 * @return the start date in the interval to remove.
	 */
	public Date getBeginDate() {
		return beginDate;
	}

	/**
	 * @return the end date in the interval to remove.
	 */
	public Date getEndDate() {
		return endDate;
	}


	public void readExternal(ObjectInput in) throws IOException,
			ClassNotFoundException {
		in.readInt();
		type = in.readInt();
		beginDate = new Date(in.readLong());
		endDate = new Date(in.readLong());
	}

	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(RequestAndResponseManager.REQUESTTYPE_GKS_TIMEREMKEYS);
		out.writeInt(type);
		out.writeLong(beginDate.getTime());
		out.writeLong(endDate.getTime());		
	}

}
