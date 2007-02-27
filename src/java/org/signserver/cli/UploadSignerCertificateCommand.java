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

import java.security.cert.X509Certificate;
import java.util.Collection;

import org.ejbca.util.CertTools;


 

/**
 * Commands that uploads a PEM certificate to a singers config.
 *
 * @version $Id: UploadSignerCertificateCommand.java,v 1.1 2007-02-27 16:18:07 herrvendil Exp $
 */
public class UploadSignerCertificateCommand extends BaseCommand {
	
	
	
    /**
     * Creates a new instance of SetPropertyCommand
     *
     * @param args command line arguments
     */
    public UploadSignerCertificateCommand(String[] args) {
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
	       throw new IllegalAdminCommandException("Usage: signserver uploadsignercertificate <signerid> <filename>\n" + 
	       		                                  "Example: signserver uploadsignercertificate 1 /home/user/singercert.pem\n\n");	       
	    }	
        try {            
        	
        	int signerid = getWorkerId(args[1], hostname);
        	checkThatWorkerIsSigner(signerid,hostname);
        	
        	String filename = args[2];
            Collection certs = CertTools.getCertsFromPEM(filename);
            if(certs.size() == 0){
            	throw new IllegalAdminCommandException("Invalid PEM file, couldn't find any certificate");
            }
            X509Certificate cert = (X509Certificate) certs.iterator().next();
                    	
        	        	        
        	this.getOutputStream().println("Uploading the following signer certificate  : \n");
            printCert(cert);        			                       
        	
        	getSignSession(hostname).uploadSignerCertificate(signerid, cert);

        	
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }

    // execute
    
	public int getCommandType() {
		return TYPE_EXECUTEONMASTER;
	}
}
