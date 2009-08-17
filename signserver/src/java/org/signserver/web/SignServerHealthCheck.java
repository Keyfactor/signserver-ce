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

package org.signserver.web;

import java.sql.Connection;
import java.sql.Statement;
import java.util.Iterator;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.ui.web.pub.cluster.IHealthCheck;
import org.ejbca.util.JDBCUtil;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;



/**
 * TSA Health Checker. 
 * 
 * Does the following system checks.
 * 
 * * Not about to run out if memory (configurable through web.xml with param "MinimumFreeMemory")
 * * Database connection can be established.
 * * All SignerTokens are aktive if not set as offline.
 * 
 * @author Philip Vendil
 * @version $Id$
 */

public class SignServerHealthCheck implements IHealthCheck {
	
	private static Logger log = Logger.getLogger(SignServerHealthCheck.class);

	
	private IGlobalConfigurationSession.ILocal globalConfigurationSession;
    private IGlobalConfigurationSession.ILocal getGlobalConfigurationSession(){
    	if(globalConfigurationSession == null){
    		try{
    		  Context context = new InitialContext();
    		  globalConfigurationSession =  (org.signserver.ejb.interfaces.IGlobalConfigurationSession.ILocal) context.lookup(IGlobalConfigurationSession.ILocal.JNDI_NAME);
    		}catch(NamingException e){
    			log.error(e);
    		}
    	}
    	
    	return globalConfigurationSession;
    }

	private IWorkerSession.ILocal signserversession;
	
    private IWorkerSession.ILocal getWorkerSession(){
    	if(signserversession == null){
    		try{
    		  Context context = new InitialContext();
    		  signserversession =  (org.signserver.ejb.interfaces.IWorkerSession.ILocal) context.lookup(IWorkerSession.ILocal.JNDI_NAME);
    		}catch(NamingException e){
    			log.error(e);
    		}
    	}
    	
    	return signserversession;
    }
	
	private int minfreememory = 0;
	private String checkDBString = null;
	
	public void init(ServletConfig config) {
		minfreememory = Integer.parseInt(config.getInitParameter("MinimumFreeMemory")) * 1024 * 1024;
		checkDBString = config.getInitParameter("checkDBString");

	}

	
	public String checkHealth(HttpServletRequest request) {
		log.debug("Starting HealthCheck health check requested by : " + request.getRemoteAddr());
		String errormessage = "";
		
		errormessage += checkDB(checkDBString);
		if(errormessage.equals("")){
		  errormessage += checkMemory(minfreememory);								
		  errormessage += checkSigners();	
		
		}
		
		if(errormessage.equals("")){
			// everything seems ok.
			errormessage = null;
		}
		
		return errormessage;
	}
	
	public static String checkMemory(int minfreememory){
		String retval = "";
        if(minfreememory >= Runtime.getRuntime().freeMemory()){
          retval = "\nError Virtual Memory is about to run out, currently free memory :" + Runtime.getRuntime().freeMemory();	
        }		
		
		return retval;
	}
	
	public static String checkDB(String checkDBString){
		String retval = "";
		try{	
		  Connection con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
		  Statement statement = con.createStatement();
		  statement.execute(checkDBString);		  
		  JDBCUtil.close(con);
		}catch(Exception e){
			retval = "\nError creating connection to SignServer Database.";
			log.error("Error creating connection to SignServer Database.",e);
		}
		return retval;
	}
 	
	private String checkSigners(){
		String retval = "";		
		Iterator<Integer> iter = getGlobalConfigurationSession().getWorkers(GlobalConfiguration.WORKERTYPE_PROCESSABLE).iterator();
		while(iter.hasNext()){
			int processableId = ((Integer) iter.next()).intValue(); 
			
			try {
				WorkerStatus workerStatus =  getWorkerSession().getStatus(processableId);
				String currentMessage = workerStatus.isOK();
				if(currentMessage != null){
					retval += "\n " +currentMessage;
					log.error(currentMessage);
				}

			} catch (InvalidWorkerIdException e) {
				log.error(e.getMessage(),e);
				e.printStackTrace();
			}
		}				
		return retval;
	}
	

	
}
