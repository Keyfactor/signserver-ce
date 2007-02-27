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
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.Properties;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.signserver.common.SignTokenAuthenticationFailureException;
import org.signserver.common.SignTokenOfflineException;
import org.signserver.server.signtokens.ISignToken;

 
  
 /**
  * Commands that uploads a PEM certificate to a singers config.
  *
  * @version $Id: GenerateCertReqCommand.java,v 1.1 2007-02-27 16:18:07 herrvendil Exp $
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
             throw new IllegalAdminCommandException("Usage: signserver generatecertreq <dn> <keyid> <authCode> <cert-req-filename>\n" +
                                                    "Example: signserver generatecertreq \"CN=CertReq\" C1232123215EF3263234R2  1234 /home/user/certtreq.pem\n\n" +
                                                    "DO NOT RUN THIS COMMAND ON THE SERVER, It can cause conflict with current card operations\n\n");
         final String dn = CertTools.stringToBCDNString(args[1]);        	        	
         final String keyid = args[2];
         final String authCode =  args[3];
         final String filename = args[4];
         try{
             // Check that keyid is a hex number
             new BigInteger(keyid,16);
         }catch(NumberFormatException e){
             throw new ErrorAdminCommandException("Error in keyId doesn't seem to ba a hex number"); 
         }
         try {
        	  
        		 
             Class implClass = Class.forName("se.primeKey.caToken.card.PrimeCAToken");
			 Object obj = implClass.newInstance();
			 ISignToken card = (ISignToken) obj;
             Properties props = new Properties();
             props.setProperty("defaultKey", keyid);
             card.init(props);
             {
                 boolean activated = false;
                 while ( !activated )
                     try {
                         card.activate(authCode);
                         activated = true;
                     } catch ( SignTokenAuthenticationFailureException e ) {
                    	 throw new ErrorAdminCommandException(e); 
                     } catch ( SignTokenOfflineException e ) {
                         synchronized(this) {
                             wait(2000);
                         }                         
                     } 
                     

             }
             PKCS10CertificationRequest req =
                 new PKCS10CertificationRequest( "SHA1withRSA",
                                                 CertTools.stringToBcX509Name(dn),
                                                 card.getPublicKey(ISignToken.PURPOSE_SIGN),
                                                 null,
                                                 card.getPrivateKey(ISignToken.PURPOSE_SIGN), 
                                                 card.getProvider() );
             if ( !req.verify() )
                 throw new ErrorAdminCommandException("cert does not verify");
             {
                 PrintStream opstr = new PrintStream(new FileOutputStream(filename));
                 opstr.println("-----BEGIN CERTIFICATE REQUEST-----");
                 opstr.println(new String(Base64.encode(req.getEncoded(), true)));
                 opstr.println("-----END CERTIFICATE REQUEST-----");            
                 opstr.close();
             }
             this.getOutputStream().println("Certificate request for the key " + keyid + " have been created successfully\n" +
                                            "and is stored in the file " + filename );
         } catch (Exception e) {
             e.printStackTrace();
             throw new ErrorAdminCommandException(e);            
         } finally {
             System.exit(0);
         }
     }
 
 	public int getCommandType() {
			return TYPE_EXECUTEONMASTER; // Not used
	}
 
 }
 
