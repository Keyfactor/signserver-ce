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

import java.security.cert.X509Certificate;
import java.util.Collection;
import org.cesecore.util.CertTools;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.WorkerStatus;

/**
 * Commands that uploads a PEM certificate to a singers config.
 *
 * @version $Id$
 */
public class UploadSignerCertificateCommand extends AbstractAdminCommand {

    @Override
    public String getDescription() {
        return "Uploads a PEM certificate to a singers configuration";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver uploadsignercertificate <signerid or name>  <NODE | GLOB> <filename>\n"
                    + "Example: signserver uploadsignercertificate 1 GLOB /home/user/singercert.pem\n\n";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 3) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        try {
            int signerid = getWorkerId(args[0]);
            checkThatWorkerIsProcessable(signerid);

            String scope = args[1];

            if (scope.equalsIgnoreCase("NODE")) {
                scope = GlobalConfiguration.SCOPE_NODE;
            } else {
                if (scope.equalsIgnoreCase("GLOB")) {
                    scope = GlobalConfiguration.SCOPE_GLOBAL;
                } else {
                    throw new IllegalCommandArgumentsException("Error: scope must be one of 'glob' or 'node'");
                }
            }

            String filename = args[2];
            Collection<?> certs = CertTools.getCertsFromPEM(filename);
            if (certs.isEmpty()) {
                throw new IllegalCommandArgumentsException("Invalid PEM file, couldn't find any certificate");
            }
            X509Certificate cert = (X509Certificate) certs.iterator().next();

            this.getOutputStream().println("Uploading the following signer certificate  : \n");
            WorkerStatus.printCert(cert, getOutputStream());

            getWorkerSession().uploadSignerCertificate(signerid, cert.getEncoded(), scope);
            return 0;
        } catch (IllegalCommandArgumentsException ex) {
            throw ex;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
}
