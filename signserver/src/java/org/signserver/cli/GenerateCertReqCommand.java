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

import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.PKCS10CertReqInfo;

 
  
 /**
  * Commands that requests a signer to generate a PKCS10 certificate request 
  *
  * @version $Id: GenerateCertReqCommand.java,v 1.2 2007-03-07 07:41:20 herrvendil Exp $
  */
 public class GenerateCertReqCommand extends BaseCommand {
     
     /**
      * Creates a new instance of SetPropertyCommand
      *
      * @param args command line arguments
      */
     public GenerateCertReqCommand(String[] args) {
         super(args);        
     }
     
     /**
      * Runs the command
      *
      * @throws IllegalAdminCommandException Error in command args
      * @throws ErrorAdminCommandException Error running command
      */
     public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
         if (args.length != 5)
             throw new IllegalAdminCommandException("Usage: signserver generatecertreq <-host hostname (optional)> <workerid> <dn> <signature algorithm>  <cert-req-filename>\n" +
                                                    "Example: signserver generatecertreq 1 \"CN=TestCertReq\"  \"SHA1WithRSA\" /home/user/certtreq.pem\n\n" );

         try{
        	 
        	 final String workerid = args[1];        	        	
        	 final String dn= args[2];
        	 final String sigAlg =  args[3];
        	 final String filename = args[4];
        	 
        	 int id = 0;

        	 if(workerid.substring(0, 1).matches("\\d")){ 
        		 id = Integer.parseInt(workerid);        		            		
        	 }else{
        		 // named worker is requested
        		 id = getSignSession(hostname).getSignerId(workerid);
        		 if(id == 0){
        			 throw new IllegalAdminCommandException("Error: No worker with the given name could be found");
        		 }
        	 }
        	 
        	 PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo(sigAlg,dn,null);
        	 Base64SignerCertReqData reqData = (Base64SignerCertReqData) getSignSession(hostname).getCertificateRequest(id, certReqInfo);

        	 FileOutputStream fos = new FileOutputStream(filename);
        	 fos.write(reqData.getBase64CertReq());
        	 fos.close();
         
        	 getOutputStream().println("PKCS10 Request successfully written to file " + filename);
         
         } catch (Exception e) {             
             throw new ErrorAdminCommandException(e);            
         }
     }
 
 	public int getCommandType() {
			return TYPE_EXECUTEONMASTER; // Not used
	}
 
 }
 
