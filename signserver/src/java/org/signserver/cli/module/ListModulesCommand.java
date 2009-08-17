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

package org.signserver.cli.module;

import org.signserver.cli.ErrorAdminCommandException;
import org.signserver.cli.IllegalAdminCommandException;



/**
 * Command used to list all available modules for the cluster class loader 
 *
 * @version $Id$
 * @author Philip Vendil
 */
public class ListModulesCommand extends BaseModuleCommand {
	
	
	
    /**
     * Creates a new instance of ListModulesCommand
     *
     * @param args command line arguments
     */
    public ListModulesCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
    	if(!isClusterClassLoaderEnabled()){
    		System.exit(-1);
    	}
    	
    	String helpMessage = "Usage: signserver module list (showjars (optional))\n\n" + 
        "Example 1: 'signserver module list' lists all available modules with " +
        "            version and parts.\n" +
        "Example 2: 'signserver module list showjars' lists all available modules  " +
        "           and also lists all jars included in each part.";
        if (args.length < 2 || args.length > 3) {
	       throw new IllegalAdminCommandException(helpMessage); 
	       		                                  	       
	    }	
        boolean showjars = args.length == 3;
        if(args.length == 3 && !args[2].equalsIgnoreCase("showjars")){
 	       throw new IllegalAdminCommandException(helpMessage);         	
        }        
        
        try {    
        	getOutputStream().println("Listing all available modules :");
        	String[] moduleNames = getCommonAdminInterface(hostname).listAllModules();
        	if(moduleNames.length == 0){
        		getOutputStream().println("  No modules found.");
        	}
        	for(String moduleName : moduleNames){
        		Integer[] versions = getCommonAdminInterface(hostname).listAllModuleVersions(moduleName);
        		for(Integer version : versions){
        			getOutputStream().println("  Module : " + moduleName + ", version " + version);
        			getOutputStream().println("    Parts : ");
        			String[] parts = getCommonAdminInterface(hostname).listAllModuleParts(moduleName, version);
        			for(String part : parts){
        				getOutputStream().println("      " + part );
        				if(showjars){
        					String[] jarNames = getCommonAdminInterface(hostname).getJarNames(moduleName, part, version);
        					getOutputStream().println("          JAR files : ");
        					for(String jarName : jarNames){
        						getOutputStream().println("            " + jarName);	
        					}
        				}
        			}
        			getOutputStream().println("");
        		}
        	}        	        
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }

	public int getCommandType() {
		return TYPE_EXECUTEONMASTER;
	}

    // execute
}
