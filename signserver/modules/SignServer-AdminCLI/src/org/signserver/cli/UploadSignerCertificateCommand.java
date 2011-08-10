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
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.WorkerStatus;

/**
 * Commands that uploads a PEM certificate to a singers config.
 *
 * @version $Id$
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
        if (args.length != 4) {
            throw new IllegalAdminCommandException("Usage: signserver uploadsignercertificate <-host hostname (optional)> <signerid or name>  <NODE | GLOB> <filename>\n"
                    + "Example: signserver uploadsignercertificate 1 GLOB /home/user/singercert.pem\n\n");
        }
        try {

            int signerid = getWorkerId(args[1], hostname);
            checkThatWorkerIsProcessable(signerid, hostname);

            String scope = args[2];

            if (scope.equalsIgnoreCase("NODE")) {
                scope = GlobalConfiguration.SCOPE_NODE;
            } else {
                if (scope.equalsIgnoreCase("GLOB")) {
                    scope = GlobalConfiguration.SCOPE_GLOBAL;
                } else {
                    throw new IllegalAdminCommandException("Error: scope must be one of 'glob' or 'node'");
                }
            }

            String filename = args[3];
            Collection<?> certs = CertTools.getCertsFromPEM(filename);
            if (certs.isEmpty()) {
                throw new IllegalAdminCommandException("Invalid PEM file, couldn't find any certificate");
            }
            X509Certificate cert = (X509Certificate) certs.iterator().next();

            this.getOutputStream().println("Uploading the following signer certificate  : \n");
            WorkerStatus.printCert(cert, getOutputStream());

            getCommonAdminInterface(hostname).uploadSignerCertificate(signerid, cert.getEncoded(), scope);

        } catch (IllegalAdminCommandException e) {
            throw e;
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
    public int getCommandType() {
        return TYPE_EXECUTEONMASTER;
    }
}
