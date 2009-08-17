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
package org.signserver.common;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.HashMap;

/**
 * Object containing extra information about a request not sent by the client
 * this could be the client certificate used to authenticate to the web server,
 * remote IP of the client or other information that could be useful for the worker.
 * 
 * 
 * @author Philip Vendil 1 dec 2007
 *
 * @version $Id$
 */
public class RequestContext implements Serializable{

	private static final long serialVersionUID = 1L;

	private HashMap<String,Object> context = new HashMap<String, Object>();
	
	/**
	 * Used to fetch the client certificate used for the request if there exists any, otherwise is
	 * 'null' returned.
	 */
	public static final String CLIENT_CERTIFICATE = "CLIENT_CERTIFICATE";
	
	/**
	 * Used to fetch the remote IP address used by the client if there exists any, otherwise is
	 * 'null' returned.
	 */
	public static final String REMOTE_IP          = "REMOTE_IP";
	
	/**
	 * All requests called from a CLI interface should set this setting to Boolean true.
	 */
	public static final String CALLED_FROM_CLI    = "CALLED_FROM_CLI";
	
	/**
	 * The current statistics event that a worker can use to add custom data.
	 * Is null if no statistics is performed.
	 */
	public static final String STATISTICS_EVENT    = "STATISTICS_EVENT";
	
	/**
	 * Default constructor creating an empty context.
	 */
	public RequestContext(){}
	
	/**
	 * Help constructor setting the client certificate and Remote IP
	 */
	public RequestContext(Certificate clientCertificate, String remoteIP){
		context.put(CLIENT_CERTIFICATE, clientCertificate);
		context.put(REMOTE_IP, remoteIP);
	}
	
	/**
	 * Help constructor used for calls from the RMI cli
	 */
	public RequestContext(boolean calledFromCli){
		context.put(CALLED_FROM_CLI, calledFromCli);
	}
	
	/**
	 * Retrieves specified field from the context, this could be a custom value or
	 * one of the specified constants
	 */
	public Object get(String field){
	   	return context.get(field);
	}
	
	/**
	 * Sets specified field from the context, this could be a custom value or
	 * one of the specified constants
	 */
	public void put(String field, Object data){
	   	context.put(field,data);
	}
	
	/**
	 * Removes specified field from the context, this could be a custom value or
	 * one of the specified constants
	 */
	public void remove(String field){
	   	context.remove(field);
	}
	
	public boolean isCalledFromCLI(){
	   boolean retval = false;
	   
	   if(context.get(CALLED_FROM_CLI) != null){
		   retval = (Boolean) context.get(CALLED_FROM_CLI);
	   }
	   
	   return retval;
	}
	
}
