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
import java.util.List;
import org.cesecore.util.CertTools;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.WorkerStatus;

/**
 * Command to import a certificate chain to a crypto token.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ImportCertificateChainCommand extends AbstractAdminCommand {
    
    private static final String TRYING = "Importing the following signer certificates  : \n";
    private static final String FAIL = "Invalid PEM file, couldn't find any certificate";

    @Override
    public String getDescription() {
        return "Import a certificate chain to a signer's crypto token";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver importcertificatechain <workerid> <certchain file> <alias>\n"
                    + "Example: signserver importcertificatechain 1 user1-chain.pem user1\n\n";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 3 && args.length != 4) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        
        try {
            final int signerid = getWorkerId(args[0]);
            final String filename = args[1];
            final String alias = args[2];
            String authCode = null;

            if (args.length > 3) {
                authCode = args[3];
            }
            
            final List<Certificate> certs = CertTools.getCertsFromPEM(filename);

            if (certs.isEmpty()) {
                throw new IllegalCommandArgumentsException(FAIL);
            }

            this.getOutputStream().println(TRYING);

            final ArrayList<byte[]> bcerts = new ArrayList<byte[]>();
            for (final Certificate cert : certs) {
                X509Certificate x509Cert = (X509Certificate) cert;
                bcerts.add(cert.getEncoded());
                WorkerStatus.printCert(x509Cert, getOutputStream());
                this.getOutputStream().println("\n");
            }

            getWorkerSession().importCertificateChain(signerid, bcerts, alias,
                    authCode != null ? authCode.toCharArray() : null);
            return 0;
        } catch (OperationUnsupportedException e) {
            getErrorStream().println("Error: " + e.getMessage());
            return -1;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
    
}
