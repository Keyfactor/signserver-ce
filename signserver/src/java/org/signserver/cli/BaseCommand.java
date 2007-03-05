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

package org.signserver.cli;

import java.io.PrintStream;
import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.log4j.Logger;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.SignServerUtil;
import org.signserver.common.SignerConfig;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.IGlobalConfigurationSession;
import org.signserver.ejb.IGlobalConfigurationSessionHome;
import org.signserver.ejb.SignServerSession;
import org.signserver.ejb.SignServerSessionHome;

/**
 * Base for Commands, contains useful functions
 *
 * @version $Id: BaseCommand.java,v 1.2 2007-03-05 06:48:32 herrvendil Exp $
 */
public abstract class BaseCommand implements IAdminCommand{
	

	
    /** Log4j instance for Base */
    private static Logger baseLog = Logger.getLogger(BaseCommand.class);
    /** Log4j instance for actual class */
    private Logger log;

    /** The SignSession home bean */
    private SignServerSessionHome signhome = null;
    private IGlobalConfigurationSessionHome globalConfigurationSessionHome;
    
    /** Where print output of commands */
    private PrintStream outStream = System.out;

    /** holder of argument array */
    protected String[] args = null;
	private SignServerSession signsession;
	private IGlobalConfigurationSession globalConfigurationSession;

    /**
     * Creates a new default instance of the class
     *
     */
    public BaseCommand(String[] args) {
        init(args,  System.out);
        SignServerUtil.installBCProvider();
    }
    
    protected void printCert(X509Certificate cert){
    	DateFormat df = DateFormat.getDateInstance();        
    	
    	this.getOutputStream().println("DN : " + cert.getSubjectDN().toString());
    	this.getOutputStream().println("SerialNumber : " + cert.getSerialNumber().toString(16));
    	this.getOutputStream().println("Issuer DN : " + cert.getIssuerDN().toString());
    	this.getOutputStream().println("Valid from :" +  df.format(cert.getNotBefore()));
    	this.getOutputStream().println("Valid to : " +  df.format(cert.getNotAfter()));
    	this.getOutputStream().println("\n\n");
    }
    
    protected void printAuthorizedClients(WorkerConfig config){
    	Iterator iter = new SignerConfig(config).getAuthorizedClients().iterator();
    	while(iter.hasNext()){
    		AuthorizedClient client = (AuthorizedClient) iter.next();
    		this.getOutputStream().println("  " + client.getCertSN() + ", " + client.getIssuerDN() + "\n");
    	}
    }

    /**
     * Initialize a new instance of BaseCommand
     *
     * @param args command line arguments
     * @param outStream stream where commands write its output
     */
    protected void init(String[] args,  PrintStream outStream) {
        //log = Logger.getLogger(this.getClass());
    	
        this.args = args;
        if( outStream != null ) {
          this.outStream = outStream;
        }
    }

    /**
     * Gets InitialContext
     *
     * @return InitialContext
     */
    protected InitialContext getInitialContext(String hostname) throws NamingException {
        baseLog.debug(">getInitialContext()");

        try {
        	Hashtable props = new Hashtable();
        	props.put(
        		Context.INITIAL_CONTEXT_FACTORY,
        		"org.jnp.interfaces.NamingContextFactory");
        	props.put(
        		Context.URL_PKG_PREFIXES,
        		"org.jboss.naming:org.jnp.interfaces");
        	props.put(Context.PROVIDER_URL, "jnp://" + hostname +":1099");
        	InitialContext cacheCtx = new InitialContext(props);
            baseLog.debug("<getInitialContext()");
            return cacheCtx;
        } catch (NamingException e) {
            baseLog.error("Can't get InitialContext", e);
            throw e;
        }
    } // getInitialContext


    /** Gets SignServerSession Remote
     *@return SignServerSession
     */
    protected SignServerSession getSignSession(String hostname) throws Exception{
    	
        if(signhome == null){	
          Context ctx = getInitialContext(hostname);
          signhome = (SignServerSessionHome) javax.rmi.PortableRemoteObject.narrow(ctx.lookup("SignServerSession"), SignServerSessionHome.class );            
          signsession = signhome.create();          
        } 
        
		return signsession;
     } // getSignSession
    

    /** Gets GlobalConfigurationSession Remote
     *@return SignServerSession
     */
    protected IGlobalConfigurationSession getGlobalConfigurationSession(String hostname) throws Exception{
    	
        if(globalConfigurationSessionHome == null){	
          Context ctx = getInitialContext(hostname);
          globalConfigurationSessionHome = (IGlobalConfigurationSessionHome) javax.rmi.PortableRemoteObject.narrow(ctx.lookup("GlobalConfigurationSession"), IGlobalConfigurationSessionHome.class );            
          globalConfigurationSession = globalConfigurationSessionHome.create();          
        } 
        
		return globalConfigurationSession;
     } // getSignSession
    
    /**
     * Logs a message with priority DEBUG
     *
     * @param msg Message
     */
    public void debug(String msg) {
        log.debug(msg);
    }

    /**
     * Logs a message and an exception with priority DEBUG
     *
     * @param msg Message
     * @param t Exception
     */
    public void debug(String msg, Throwable t) {
        log.debug(msg, t);
    }

    /**
     * Logs a message with priority INFO
     *
     * @param msg Message
     */
    public void info(String msg) {
        log.info(msg);
    }

    /**
     * Logs a message and an exception with priority INFO
     *
     * @param msg Message
     * @param t Exception
     */
    public void info(String msg, Throwable t) {
        log.info(msg, t);
    }

    /**
     * Logs a message with priority ERROR
     *
     * @param msg Message
     */
    public void error(String msg) {
        log.error(msg);
    }

    /**
     * Logs a message and an exception with priority ERROR
     *
     * @param msg Message
     * @param t Exception
     */
    public void error(String msg, Throwable t) {
        log.error(msg, t);
    }


    /**
     * Return the PrintStream used to print output of commands
     *
     */
    public PrintStream getOutputStream() {
        return outStream;
    }

    /**
     * Set the PrintStream used to print output of commands
     *
     * @param outStream stream where commands write its output
     */
    public void setOutputStream(PrintStream outStream) {
    if( outStream == null )
        this.outStream = System.out;
    else
        this.outStream = outStream;
    }   
    
    /**
     * Help Method that retrieves the id of a worker given either
     * it's id in string format or the name of a worker
     * @throws Exception 
     * @throws RemoteException 
     */
    protected int getWorkerId(String workerIdOrName, String hostname) throws RemoteException, Exception{
    	int retval = 0;
    	
    	if(workerIdOrName.substring(0, 1).matches("\\d")){
    		retval = Integer.parseInt(workerIdOrName);    		
    	}else{
    		retval = getSignSession(hostname).getSignerId(workerIdOrName);
    		if(retval == 0){
    			throw new IllegalAdminCommandException("Error: No worker with the given name could be found");
    		}
    	}
    	
    	return retval;
    }
    
    /**
     * Help method that checks that the current worker is a signer
     * @throws Exception 
     * @throws RemoteException 
     */
    public void checkThatWorkerIsSigner(int signerid, String hostname) throws RemoteException, Exception{
    	Collection signerIds = getGlobalConfigurationSession(hostname).getWorkers(GlobalConfiguration.WORKERTYPE_SIGNERS);
    	if(!signerIds.contains(new Integer(signerid))){
    		throw new IllegalAdminCommandException("Error: given workerId doesn't seem to point to any signer in the system.");
    	}
    	
    }
    


} //BaseCommand
