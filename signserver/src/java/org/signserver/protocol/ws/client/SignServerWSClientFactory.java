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

package org.signserver.protocol.ws.client;

import javax.net.ssl.SSLSocketFactory;

import org.apache.log4j.Logger;

/**
 * Factory used to create a ISignServerWSClient with a given
 * high availability policy.
 * 
 * See CLIENTTYPE_ constants to see which that are available.
 * 
 * 
 * @author Philip Vendil 10 nov 2007
 *
 * @version $Id$
 */

public class SignServerWSClientFactory {
	private static Logger log = Logger.getLogger(SignServerWSClientFactory.class);
	
	public static final String CLIENTTYPE_CALLFIRSTNODEWITHSTATUSOK = "org.signserver.protocol.ws.client.CallFirstNodeWithStatusOKWSClient";

	/** Default timeout in milliseconds */
    public static final int DEFAULT_TIMEOUT = 20000; // 10s
    
    /** Default port of the server */
    public static final int DEFAULT_PORT = 8080;
    public static final int SECURE_PORT = 8443;
    
    public static final String PROTOCOL = "http://";
    public static final String SECURE_PROTOCOL = "https://";
    public static final String DEFAULT_WSDL_URL = "/signserver/signserverws/signserverws?wsdl";
	
    /**
     * Generates a SignServerWSClient using default port, timeout and wsdlURL.
     * 
     * @param clientType One of the CLIENTTYPE_ constants indication the High-Availability policy that should be used.
     * @param hosts host names of the server to connect to.
     * @param useHTTPS indicates if HTTPS should be used.
     */
    public ISignServerWSClient generateSignServerWSClient(String clientType, String[] hosts, boolean useHTTPS, IFaultCallback faultCallback){
       return generateSignServerWSClient(clientType, hosts, useHTTPS, faultCallback, DEFAULT_PORT, DEFAULT_TIMEOUT,DEFAULT_WSDL_URL);
    }
    
    /**
     * Generates a SignServerWSClient using default timeout and wsdlURL but
     * with a port specified.
     * 
     * @param clientType One of the CLIENTTYPE_ constants indication the High-Availability policy that should be used.
     * @param hosts host names of the server to connect to.
     * @param useHTTPS indicates if HTTPS should be used.
     * @param port to connect to
     */
    public ISignServerWSClient generateSignServerWSClient(String clientType,String[] hosts, boolean useHTTPS, IFaultCallback faultCallback , int port ){
    	return generateSignServerWSClient(clientType, hosts, useHTTPS, faultCallback, port, DEFAULT_TIMEOUT,DEFAULT_WSDL_URL);
    }
    
    /**
     * Generates a SignServerWSClient using default wsdlURL but
     * with a port and timeout specified.
     * 
     * @param clientType One of the CLIENTTYPE_ constants indication the High-Availability policy that should be used.
     * @param hosts host names of the server to connect to.
     * @param useHTTPS indicates if HTTPS should be used.
     * @param port to connect to
     * @param timeOut in milliseconds
     */
    public ISignServerWSClient generateSignServerWSClient(String clientType,String[] hosts, boolean useHTTPS,IFaultCallback faultCallback,int port, int timeOut){
    	return generateSignServerWSClient(clientType, hosts, useHTTPS, faultCallback, DEFAULT_PORT, timeOut,DEFAULT_WSDL_URL);
    }
    
    /**
     * Generates a SignServerWSClient using specified
     * port and timeout and wsdlURL specified.
     * 
     * @param clientType One of the CLIENTTYPE_ constants indication the High-Availability policy that should be used.
     * @param hosts host names of the server to connect to.
     * @param useHTTPS indicates if HTTPS should be used.
     * @param port to connect to
     * @param timeOut in milliseconds
     * @param customAppURI the path to the sign server URI where the WS is deployed.
     */
    public ISignServerWSClient generateSignServerWSClient(String clientType,String[] hosts,  boolean useHTTPS, IFaultCallback faultCallback, int port, int timeOut, String customAppURI){
    	return generateSignServerWSClient(clientType, hosts, useHTTPS, faultCallback, DEFAULT_PORT, timeOut,DEFAULT_WSDL_URL,null);
    }
    
    /**
     * Generates a SignServerWSClient using specified
     * port, timeout, wsdlURL and custom SSLSocketFactory specified.
     * 
     * @param clientType One of the CLIENTTYPE_ constants indication the High-Availability policy that should be used.
     * @param hosts host names of the server to connect to.
     * @param useHTTPS indicates if HTTPS should be used.
     * @param port to connect to
     * @param timeOut in milliseconds
     * @param customAppURI the path to the sign server URI where the WS is deployed.
     * @param sSLSocketFactory the SSLSocketFactory to use, null means that the Default 
     * SSLSocketFactory will be used if necessary. 
     */
    public ISignServerWSClient generateSignServerWSClient(String clientType,String[] hosts,  boolean useHTTPS, IFaultCallback faultCallback, int port, int timeOut, String customAppURI, SSLSocketFactory sSLSocketFactory){
    	ISignServerWSClient retval = null;
    	try {
			retval = (ISignServerWSClient) this.getClass().getClassLoader().loadClass(clientType).newInstance();
			
			int tmpPort = port;
			if(useHTTPS && port==DEFAULT_PORT){
				tmpPort = SECURE_PORT;
			}
			
			retval.init(hosts, tmpPort, timeOut, customAppURI, useHTTPS, faultCallback, sSLSocketFactory);
			
		} catch (Exception e) {
			log.error("Error creating SignServiceWSClient of type " + clientType,e);
		}
		
		return retval;
    }
	
}
