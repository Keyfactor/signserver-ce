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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.signserver.server.WorkerFactory;
 


/**
 * Implements the signserver command line interface
 *
 * @version $Id: signserver.java,v 1.2 2007-03-07 07:41:19 herrvendil Exp $
 */
public class signserver {
    /**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        try {
        	String hostname = checkHostParameter(args);
        	if(hostname != null){
        		args = removeHostParameters(args);
        	}
        	
        	
            IAdminCommand cmd = SignServerCommandFactory.getCommand(args);

            
            if (cmd != null) {
            	                                                    
                if(cmd.getCommandType() == IAdminCommand.TYPE_EXECUTEONMASTER){
                	if(hostname == null){
                	  hostname = signserver.getMasterHostname();
                	}
                	System.out.println("===========================================");
                	System.out.println("  Executing Command on host : " + hostname);
                	System.out.println("===========================================\n\n");
                	cmd.execute(hostname);
                }else{
                    if(cmd.getCommandType() == IAdminCommand.TYPE_EXECUTEONALLNODES){
                    	String[] hostnames = signserver.getAllHostnames();
                    	for(int i=0;i<hostnames.length;i++){
                    	  IAdminCommand c = SignServerCommandFactory.getCommand(args);
                          System.out.println("===========================================");
                    	  System.out.println("Executing Command on host : " + hostnames[i]);
                      	  System.out.println("===========================================\n\n");
                    	  c.execute(hostnames[i]);
                    	}  
                    }else{
                    	cmd.execute(null);
                    }
                }
                
            } else {
                System.out.println("Usage: signserver < getstatus | getconfig | reload | setproperty | setproperties | setpropertyfromfile | removeproperty " +
                		           "| dumpproperties | listauthorizedclients | addauthorizedclient | removeauthorizedclient | uploadsignercertificate " +
                		           "| uploadsignercertificatechain | activatesigntoken | deactivatesigntoken | generatecertreq | archive > \n");
                System.out.println("Available archive commands : Usage: signserver archive < findfromarchiveid | findfromrequestip | findfromrequestcert > \n");
                System.out.println("Each basic command give more help");
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());            
            System.exit(-1);
        }
    }
    
    private static String getMasterHostname()throws IOException{
    	Properties props = getProperties();
    	String hostname = props.getProperty("hostname.masternode");
    	return hostname;
    }
    
    private static String[] getAllHostnames()throws IOException{
    	Properties props = getProperties();
    	String hosts = props.getProperty("hostname.allnodes");
    	
    	return hosts.split(";");
    }
    
    private static Properties getProperties() throws IOException{
        String propsfile = "signserver_cli.properties";
        InputStream is = new FileInputStream(propsfile);
        Properties properties = new Properties();
        properties.load(is);
        WorkerFactory.flush();
        is.close();
        return properties;
    }
    

    
    /**
     * Method that checks if a '-host host' parameter exists 
     * and return the given hostname.
     * @return hostname or null if host param didn't exist
     */
    private static String checkHostParameter(String[] args) {
    	String retval = null;

		for(int i=0;i<args.length-1;i++){
			if(args[i].equalsIgnoreCase("-host")){
				retval = args[i+1];
				break;
			}			
		}
		
		return retval;
	}
    
    /**
     * Method that checks if a '-host host' parameter exist and removes the parameters
     * and returns a new args array
     * @return a args arrray with -host paramter removed
     */
    private static String[] removeHostParameters(String[] args) {
    	String[] retval = null;
    	boolean found = false;
    	int index = 0;
		for(int i=0;i<args.length-1;i++){
			if(args[i].equalsIgnoreCase("-host")){
				index = i;
				found = true;
				break;
			}
			
		}
		
		if(found){
			String newargs[] = new String[args.length -2];
			for(int i=0;i<args.length;i++){
				if(i < index ){
					newargs[i] = args[i];
				}
				if(i > index +1){
					newargs[i-2] = args[i];
				}
			}
			retval = newargs;
		}
		return retval;
	}
    
}
    



//signserver
