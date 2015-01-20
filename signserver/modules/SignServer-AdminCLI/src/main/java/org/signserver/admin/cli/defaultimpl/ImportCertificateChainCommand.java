/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
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
import org.signserver.common.WorkerStatus;

/**
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ImportCertificateChainCommand extends AbstractAdminCommand {
    
    private static final String TRYING = "Importing the following signer certificates  : \n";
    private static final String FAIL = "Invalid PEM file, couldn't find any certificate";

    @Override
    public String getDescription() {
        return "Import a certificate chain to a signer's crypto token.";
    }

    @Override
    public String getUsages() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 3) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        
        try {
            final int signerid = getWorkerId(args[0]);
            final String filename = args[1];
            final String alias = args[2];

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

            getWorkerSession().importCertificateChain(signerid, bcerts, alias);
            return 0;
        } catch (IllegalCommandArgumentsException e) {
            throw e;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
    
}
