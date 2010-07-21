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
  * @version $Id$
  */
 public class GenerateCertReqCommand extends BaseCommand {

		protected static final int HELP = 0;
		protected static final int FAIL = 1;
		protected static final int SUCCESS = 2;
	 
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
     protected void execute(String hostname, String[] resources) throws IllegalAdminCommandException, ErrorAdminCommandException {
         if (args.length != 5 && args.length != 6) {
             throw new IllegalAdminCommandException( resources[HELP]);
         }
         try{
        	 
        	 final String workerid = args[1];        	        	
        	 final String dn= args[2];
        	 final String sigAlg =  args[3];
        	 final String filename = args[4];
                 final boolean defaultKey;
                 if (args.length > 5) {
                     if ("-nextkey".equals(args[5])) {
                         defaultKey = false;
                     } else {
                        throw new IllegalAdminCommandException( resources[HELP]);
                     }
                 } else {
                     defaultKey = true;
                 }
        	 
        	 int id = 0;

        	 if(workerid.substring(0, 1).matches("\\d")){ 
        		 id = Integer.parseInt(workerid);        		            		
        	 }else{
        		 // named worker is requested
        		 id = getCommonAdminInterface(hostname).getWorkerId(workerid);
        		 if(id == 0){
        			 throw new IllegalAdminCommandException(resources[FAIL]);
        		 }
        	 }

        	 PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo(sigAlg,dn,null);
        	 Base64SignerCertReqData reqData = (Base64SignerCertReqData) getCommonAdminInterface(hostname).genCertificateRequest(id, certReqInfo, defaultKey);
        	 if (reqData == null) {
        		 throw new Exception("Base64SignerCertReqData returned was null. Unable to generate certificate request.");
        	 }
        	 FileOutputStream fos = new FileOutputStream(filename);
        	 fos.write("-----BEGIN CERTIFICATE REQUEST-----\n".getBytes());
        	 fos.write(reqData.getBase64CertReq());
        	 fos.write("\n-----END CERTIFICATE REQUEST-----\n".getBytes());
        	 fos.close();
         
        	 getOutputStream().println(resources[SUCCESS] + filename);
         
         } catch (IllegalAdminCommandException e) {
         	throw e;  
         } catch (Exception e) {   
             throw new ErrorAdminCommandException(e);            
         }
     }
     
     public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
     	String[] resources =  {"Usage: signserver generatecertreq <-host hostname (optional)> <workerid> <dn> <signature algorithm>  <cert-req-filename> [-nextkey]\n" +
                               "Example: signserver generatecertreq 1 \"CN=TestCertReq\"  \"SHA1WithRSA\" /home/user/certtreq.pem\n"
                               + "Example: signserver generatecertreq 1 \"CN=TestCertReq\"  \"SHA1WithRSA\" /home/user/certtreq.pem -nextkey\n\n",
                               "Error: No worker with the given name could be found",
                               "PKCS10 Request successfully written to file "};
         execute(hostname,resources);   
     }
 
 	public int getCommandType() {
			return TYPE_EXECUTEONMASTER; // Not used
	}
 
 }
 
