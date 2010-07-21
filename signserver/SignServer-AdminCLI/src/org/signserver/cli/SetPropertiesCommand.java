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
import java.util.Properties;

 

/**
 * Sets properties from a given property file.
 * 
 * See the manual for the syntax of the property file
 *
 * @version $Id$
 */
public class SetPropertiesCommand extends BaseCommand {
	

	
    /**
     * Creates a new instance of SetPropertyCommand
     *
     * @param args command line arguments
     */
    public SetPropertiesCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length != 2) {
	       throw new IllegalAdminCommandException("Usage: signserver setproperties <-host hostname (optional)>  <propertyfile>\n" + 
	       		                                  "Example 1: signserver setproperties mysettings.properties\n" +
	    		                                  "Example 2: signserver setproperties -host node3.someorg.com mysettings.properties\n\n");	       
	    }	
        try {            
         
        	SetPropertiesHelper helper = new SetPropertiesHelper(getOutputStream(),getCommonAdminInterface(hostname));
        	Properties properties = loadProperties(args[1]);
        
        	getOutputStream().println("Configuring properties as defined in the file : " + args[1]);
            helper.process(properties);

        	this.getOutputStream().println("\n\n");

        } catch (IllegalAdminCommandException e) {
        	throw e;  
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }





	private Properties loadProperties(String path) {
		Properties retval = new Properties();
		try {
			retval.load(new FileInputStream(path));
		} catch (Exception e) {
			getOutputStream().println("Error reading property file : " + path);
			System.exit(-1);
		}
		
		return retval;
	}


	// execute
    
	public int getCommandType() {
		return TYPE_EXECUTEONMASTER;
	}
	

}
