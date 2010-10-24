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

import java.io.FileOutputStream;
import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import org.ejbca.util.Base64;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.WorkerConfig;

 

/**
 * Command used to dump all configured properties for a worker or all workers
 *
 * @version $Id$
 */
public class DumpPropertiesCommand extends BaseCommand {
	
	
    /**
     * Creates a new instance of SetPropertyCommand
     *
     * @param args command line arguments
     */
    public DumpPropertiesCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length != 3) {
	       throw new IllegalAdminCommandException("Usage: signserver dumpproperties <-host hostname (optional)> < all | workerid > <outfile>\n" + 
	       		                                  "Example 1: signserver dumpproperties 1 myworkerbackup.properties\n" +
	       		                                  "Example 2: signserver dumpproperties all singserverbackup.properties\n" +
	    		                                  "Example 3: signserver dumpproperties -host node3.someorg.com all singserverbackup.properties\n\n");	       
	    }	
        try {            
        	
        	String outfile = args[2];        	
        	String workerid = args[1];
        	
        	Properties outProps = new Properties();

        	if(workerid.substring(0, 1).matches("\\d")){ 
        		dumpWorkerProperties(hostname, Integer.parseInt(workerid),outProps);        		            		
        	}else{
        		if(workerid.trim().equalsIgnoreCase("ALL")){
        			dumpAllProperties(hostname, outProps);            			
        		}else{
        			// named worker is requested
        			int id = getCommonAdminInterface(hostname).getWorkerId(workerid);
        			if(id == 0){
        				throw new IllegalAdminCommandException("Error: No worker with the given name could be found");
        			}
            		dumpWorkerProperties(hostname, id,outProps);        			
        		}
        	}
        	
        	FileOutputStream fos = new FileOutputStream(outfile);
        	outProps.store(fos, null);
        	fos.close();
        	getOutputStream().println("Properties successfully dumped into file " + outfile);

        	this.getOutputStream().println("\n\n");

        } catch (IllegalAdminCommandException e) {
        	throw e;  
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }

	private void dumpAllProperties(String hostname, Properties outProps) throws RemoteException, Exception {		
		List<Integer> workers = getCommonAdminInterface(hostname).getWorkers(GlobalConfiguration.WORKERTYPE_ALL);
		
		// First output all global properties
		GlobalConfiguration gc = getCommonAdminInterface(hostname).getGlobalConfiguration();
		Enumeration<String> en = gc.getKeyEnumeration();
		while(en.hasMoreElements()){
			String next =  en.nextElement();
			outProps.put(next, gc.getProperty(next));
		}
		Iterator<Integer> iter = workers.iterator();
		while(iter.hasNext()){
			Integer next = (Integer) iter.next();
			dumpWorkerProperties(hostname, next, outProps);
		}				
	}

	private void dumpWorkerProperties(String hostname, int workerId, Properties outProps) throws RemoteException, Exception {
		GlobalConfiguration gc = getCommonAdminInterface(hostname).getGlobalConfiguration();
		Enumeration<String> en = gc.getKeyEnumeration();
		while(en.hasMoreElements()){
			String next = en.nextElement();
			if(next.substring(5).startsWith("WORKER" + workerId)){
			  outProps.put(next, gc.getProperty(next));
			}
		}	
		
		WorkerConfig workerConfig = getCommonAdminInterface(hostname).getCurrentWorkerConfig(workerId);
		Enumeration<?> e = workerConfig.getProperties().keys();
		Properties workerProps = workerConfig.getProperties();
		while(e.hasMoreElements()){
			String key = (String) e.nextElement();
			outProps.setProperty("WORKER" + workerId +"."+key, workerProps.getProperty(key));
		}
		
		// Also dump Authorized Clients and/or signer certificates
		ProcessableConfig pConfig = new ProcessableConfig(workerConfig);
		if(pConfig.getSignerCertificate() != null){
			X509Certificate cert = pConfig.getSignerCertificate();
			outProps.setProperty("WORKER" + workerId+SetPropertiesHelper.SIGNERCERTIFICATE, new String(Base64.encode(cert.getEncoded(), false)));
		}
		if(pConfig.getSignerCertificateChain() != null){
			Collection<Certificate> certs = pConfig.getSignerCertificateChain();
			Iterator<Certificate> iter2 = certs.iterator(); 
			String chainValue = "";
			while (iter2.hasNext()) {
			  Certificate cert = iter2.next();
			  String certData = new String(Base64.encode(cert.getEncoded(), false));
			  if(chainValue.equals("")){
				  chainValue = certData;
			  }else{
				  chainValue += ";" + certData;
			  }
			}
			
			outProps.setProperty("WORKER" + workerId+SetPropertiesHelper.SIGNERCERTCHAIN, chainValue);
		}
		
		if(pConfig.getAuthorizedClients().size() > 0){
			Collection<AuthorizedClient> aClients = pConfig.getAuthorizedClients();
			int i = 1;
			for(AuthorizedClient client : aClients){
				outProps.setProperty("WORKER" + workerId+SetPropertiesHelper.AUTHCLIENT + i , client.getCertSN() + ";" + client.getIssuerDN());								
				i++;
			}
		}				
	}

	// execute
    
	public int getCommandType() {
		return TYPE_EXECUTEONMASTER;
	}
	

}
