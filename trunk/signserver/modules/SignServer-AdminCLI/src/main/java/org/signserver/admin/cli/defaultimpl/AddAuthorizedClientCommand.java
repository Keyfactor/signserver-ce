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
package org.signserver.admin.cli.defaultimpl;

import java.math.BigInteger;
import java.security.Principal;
import java.security.cert.X509Certificate;
import org.cesecore.util.CertTools;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.SignServerUtil;

/**
 * Adds an authorized client to a signer
 *
 * @version $Id$
 */
public class AddAuthorizedClientCommand extends AbstractAdminCommand {

    
    @Override
    public String getDescription() {
        return "Authorizes a client";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver addauthorizedclient <signerid> <certificatesn (hex)> <issuerdn>\n"
        	 + "       signserver addauthorizedclient <signerid> <certificate-filename>\n"
                    + "Example 1: signserver addauthorizedclient 1 EF34242D2324 \"CN=Test Root CA\"\n"
                    + "Example 2: signserver addauthorizedclient 1 EF3456789ABC \"CN=Client,O=Test Organization,C=SE\"\n"
                    + "Example 3: signserver addauthorizedclient 1 client.pem\n\n";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        
        if (args.length != 3 && args.length != 2) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }

        try {
            int signerid = getWorkerId(args[0]);
            String certsn = null;
            String issuerdn = null;
            BigInteger sn = null;
            checkThatWorkerIsProcessable(signerid);
            
            if (args.length == 3) {
            	certsn = args[1];
            	issuerdn = CertTools.stringToBCDNString(args[2]);
            	sn = new BigInteger(certsn, 16);  // Test that it's a vaild number (hex)
            } else {
            	// read SN and DN from the supplied certificate...
            	String filename = args[1];
            	X509Certificate cert = SignServerUtil.getCertFromFile(filename);	
            	
            	sn = cert.getSerialNumber();
            	certsn = sn.toString(16);  // needed for the infomational output below
            	Principal dn = cert.getIssuerX500Principal();
            	issuerdn = CertTools.stringToBCDNString(dn.getName());
            }

            AuthorizedClient authClient = new AuthorizedClient(sn.toString(16), issuerdn);

            this.getOutputStream().println("Adding the client certificate with sn " + sn.toString(16) + " and issuerDN : " + issuerdn + " for signer " + signerid + "\n");
            this.getOutputStream().println("See current configuration with the listauthorizedclients command, activate it with the reload command\n");

            getWorkerSession().addAuthorizedClient(signerid, authClient);


            printAuthorizedClients(getWorkerSession().getAuthorizedClients(signerid));

            this.getOutputStream().println("\n\n");
            return 0;

        } catch (IllegalArgumentException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());  
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }

}
