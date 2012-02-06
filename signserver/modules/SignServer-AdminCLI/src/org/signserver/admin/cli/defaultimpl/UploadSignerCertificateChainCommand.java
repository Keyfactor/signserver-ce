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

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import org.ejbca.util.CertTools;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.WorkerStatus;

/**
 * Commands that uploads a PEM certificate to a signers config.
 *
 * @version $Id$
 */
public class UploadSignerCertificateChainCommand extends AbstractAdminCommand {

    private static final String HELP = "Usage: signserver uploadsignercertificatechain <signerid | name> <NODE | GLOB> <filename> \n"
            + "Example: signserver uploadsignercertificatechain 1 GLOB /home/user/signercertchain.pem\n\n";
    private static final String TRYING = "Uploading the following signer certificates  : \n";
    private static final String BADPEM = "Error: scope must be one of 'glob' or 'node'";
    private static final String FAIL = "Invalid PEM file, couldn't find any certificate";

    @Override
    public String getDescription() {
        return "Uploads a PEM certificate to a signers config";
    }

    @Override
    public String getUsages() {
        return HELP;
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 3) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        try {

            int signerid = getWorkerId(args[0]);

            String scope = args[1];

            if (scope.equalsIgnoreCase("NODE")) {
                scope = GlobalConfiguration.SCOPE_NODE;
            } else {
                if (scope.equalsIgnoreCase("GLOB")) {
                    scope = GlobalConfiguration.SCOPE_GLOBAL;
                } else {
                    throw new IllegalCommandArgumentsException(FAIL);
                }
            }

            String filename = args[2];
            Collection<Certificate> certs = CertTools.getCertsFromPEM(filename);
            if (certs.isEmpty()) {
                throw new IllegalCommandArgumentsException(BADPEM);
            }

            this.getOutputStream().println(TRYING);

            ArrayList<byte[]> bcerts = new ArrayList<byte[]>();
            Iterator<Certificate> iter = certs.iterator();
            while (iter.hasNext()) {
                X509Certificate cert = (X509Certificate) iter.next();
                bcerts.add(cert.getEncoded());
                WorkerStatus.printCert(cert, getOutputStream());
                this.getOutputStream().println("\n");
            }

            getWorkerSession().uploadSignerCertificateChain(signerid, bcerts, scope);
            return 0;
        } catch (IllegalCommandArgumentsException e) {
            throw e;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
}
