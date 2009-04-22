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

package org.signserver.cli.groupkeyservice;

import org.signserver.cli.ErrorAdminCommandException;
import org.signserver.cli.IllegalAdminCommandException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.groupkeyservice.common.PregenerateKeysRequest;
import org.signserver.groupkeyservice.common.PregenerateKeysResponse;



/**
 * Command used to tell a group key service to pregenerate a number of keys. 
 *
 * @version $Id$
 * @author Philip Vendil
 */
public class PregenerateKeyCommand extends BaseGroupKeyServiceCommand {
	
	private static int NUMBEROFKEYSPERREQUESTS = 100;
	
    /**
     * Creates a new instance of SetPropertyCommand
     *
     * @param args command line arguments
     */
    public PregenerateKeyCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length != 4) {
	       throw new IllegalAdminCommandException("Usage: signserver groupkeyservice pregeneratekeys <workerId or name> <number of keys>\n" + 
	       		                                  "Example: signserver groupkeyservice pregeneratekeys GroupKeyService1 1000\n\n");	       
	    }	
        try {            
        	int workerId = getWorkerId(args[2], hostname);
        	isWorkerGroupKeyService(hostname,workerId);
        	
        	int numberOfKeys = 0;
        	try{
        		numberOfKeys = Integer.parseInt(args[3]);
        	}catch(NumberFormatException e){
        		throw new IllegalAdminCommandException("Error: Parameter specifying the number of keys to generate '" + args[3] + "' can only contain digits.");
        	}
        	       	
        	int keysGenerated = 0;
        	while(keysGenerated < numberOfKeys){
        	   int keysToGenerate = NUMBEROFKEYSPERREQUESTS;
               if((numberOfKeys - keysGenerated) < NUMBEROFKEYSPERREQUESTS){
            	   keysToGenerate = (numberOfKeys - keysGenerated);
               }
               this.getOutputStream().println("Pregenerating keys " + (keysGenerated +1) + " to " + (keysGenerated + keysToGenerate));
        	   PregenerateKeysRequest req = new PregenerateKeysRequest(keysToGenerate);
        	   PregenerateKeysResponse res = (PregenerateKeysResponse) getCommonAdminInterface(hostname).processRequest(workerId, req);
        	   if(res.getNumberOfKeysGenerated() != keysToGenerate){
        		   throw new ErrorAdminCommandException("Error requested number of keys '"+keysToGenerate + "' wasn't pregenerated only '" + res.getNumberOfKeysGenerated() + "' were generated.");
        	   }
               keysGenerated += keysToGenerate;
        	}
        	this.getOutputStream().println("\n\n" + keysGenerated + " Pregenerated successfully.\n");
     
        	
        } catch (CryptoTokenOfflineException e) {
        	throw new IllegalAdminCommandException("Error, Group key service " + args[2] + " : Crypotoken is off-line.");   
        } catch (IllegalAdminCommandException e) {
        	throw e;  
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }

	public int getCommandType() {
		return TYPE_EXECUTEONMASTER;
	}

    // execute
}
