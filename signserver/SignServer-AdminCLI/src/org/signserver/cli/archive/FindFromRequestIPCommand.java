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


package org.signserver.cli.archive;

import java.io.File;
import java.io.FileOutputStream;
import java.util.Iterator;
import java.util.List;

import org.signserver.cli.BaseCommand;
import org.signserver.cli.ErrorAdminCommandException;
import org.signserver.cli.IllegalAdminCommandException;
import org.signserver.common.ArchiveDataVO;




/**
 * Returns all archive datas requested from given IP
 *
 * @version $Id$
 */
public class FindFromRequestIPCommand extends BaseCommand {
	
	
	
    /**
     * Creates a new instance of FindFromRequestIPCommand
     *
     * @param args command line arguments
     */
    public FindFromRequestIPCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length != 5) {
	       throw new IllegalAdminCommandException("Usage: signserver archive findfromrequestip <signerid> <requestip> <outputpath>\n" + 
	       		                                  "Example: signserver archive findfromrequestip 1 10.1.1.1 /tmp/archivedata \n\n");	       
	    }	
        try {                    	
        	int signerid = getWorkerId(args[2], hostname);
        	checkThatWorkerIsProcessable(signerid,hostname);
        	
        	String requestIP = args[3];
            File outputPath = new File(args[4]);
            if(!outputPath.exists()){
            	throw new IllegalAdminCommandException("Error output path " + args[4] + " doesn't exist\n\n");	 
            }
            if(!outputPath.isDirectory()){
            	throw new IllegalAdminCommandException("Error output path " + args[4] + " isn't a directory\n\n");	 
            }            
            
        	this.getOutputStream().println("Trying to find archive datas requested from IP " + requestIP +  "\n");
		                               	
        	List<ArchiveDataVO> result = getCommonAdminInterface(hostname).findArchiveDatasFromRequestIP(signerid,requestIP);        	        	
        	
            if(result.size() != 0){
            	Iterator<ArchiveDataVO> iter = result.iterator();
            	while (iter.hasNext()){
            	  ArchiveDataVO next =  iter.next();            	
            	  String filename = outputPath.getAbsolutePath() + "/"+ next.getArchiveId();
            	  FileOutputStream os = new FileOutputStream(filename);
            	  os.write(next.getArchiveData().getData());
            	  os.close();
            	  this.getOutputStream().println("Archive data with archiveid " + next.getArchiveId() + " written to file : " +filename + "\n\n");
            	}
            }else{
            	this.getOutputStream().println("Couldn't find any archive data from client with IP " + requestIP + " from signer " +signerid + "\n\n");
            }        	
        	
    		this.getOutputStream().println("\n\n");
        	
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
