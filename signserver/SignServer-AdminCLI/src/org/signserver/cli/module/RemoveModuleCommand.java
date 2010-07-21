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

import java.util.Arrays;

import org.signserver.cli.ErrorAdminCommandException;
import org.signserver.cli.IllegalAdminCommandException;



/**
 * Command used to remove a  modules from the cluster class loader 
 *
 * @version $Id$
 * @author Philip Vendil
 */
public class RemoveModuleCommand extends BaseModuleCommand {
	
    /**
     * Creates a new instance of RemoveModuleCommand
     *
     * @param args command line arguments
     */
    public RemoveModuleCommand(String[] args) {
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
        if (args.length != 4) {
	       throw new IllegalAdminCommandException("Usage: signserver module remove <modulename> <version>\n\n" + 
	    		                                  "Example: 'signserver module remove testmodule 2'"); 
	       		                                  	       
	    }	
        
        String moduleName = args[2];
        moduleName = moduleName.toUpperCase();
        
    	int version = 1;
    	try{
    		version = Integer.parseInt(args[3]);
    	}catch(NumberFormatException e){
    		throw new IllegalAdminCommandException("Error: Parameter specifying the module version '" + args[3] + "' can only contain digits.");
    	}
        
    	try {    

    		String[] moduleNames = getCommonAdminInterface(hostname).listAllModules();
    		if(!Arrays.asList(moduleNames).contains(moduleName)){        		
    			getOutputStream().println("  Error module with name " + moduleName + " not found.");

    		}else{
    			Integer[] versions = getCommonAdminInterface(hostname).listAllModuleVersions(moduleName);
    			if(!Arrays.asList(versions).contains(version)){
    				getOutputStream().println("  Error version " + version + " for module with name " + moduleName + " wasn't found.");
    			}else{
    				String[] parts = getCommonAdminInterface(hostname).listAllModuleParts(moduleName, version);
    				getOutputStream().println("  Removing module " + moduleName + " version " + version + " ...");
    				for(String part : parts){
    					getCommonAdminInterface(hostname).removeModulePart(moduleName, part, version);
    				}        	        
    				getOutputStream().println("  Removal of module successful.");
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
