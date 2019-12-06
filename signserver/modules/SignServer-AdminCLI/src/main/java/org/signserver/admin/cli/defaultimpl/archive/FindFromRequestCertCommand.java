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
package org.signserver.admin.cli.defaultimpl.archive;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.List;
import org.signserver.admin.cli.defaultimpl.AbstractAdminCommand;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.ArchiveDataVO;

/**
 * Returns all archive datas requested from given IP
 *
 * @version $Id$
 */
public class FindFromRequestCertCommand extends AbstractAdminCommand {

    private ArchiveCLIUtils utils = new ArchiveCLIUtils();
    
    @Override
    public String getDescription() {
        return "Returns all archive datas requested from given certificate details";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver archive findfromrequestcert <signer ID> <certificate SN (hex)> <issuerd> <outputpath>\n"
                    + "Example: signserver archive findfromrequestcert 1 EF34242D2324 \"CN=Test Root CA\" /tmp/archivedata \n\n";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 4) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        try {
            int signerid = getWorkerId(args[0]);
            checkThatWorkerIsProcessable(signerid);

            String certsn = args[1];
            String issuerdn = args[2];
            BigInteger sn = new BigInteger(certsn, 16);
            File outputPath = new File(args[3]);
            if (!outputPath.exists()) {
                throw new IllegalCommandArgumentsException("Error output path " + args[3] + " doesn't exist\n\n");
            }
            if (!outputPath.isDirectory()) {
                throw new IllegalCommandArgumentsException("Error output path " + args[3] + " isn't a directory\n\n");
            }

            this.getOutputStream().println("Trying to find archive datas requested from client with certificate " + certsn + " issued by " + issuerdn + "\n");

            List<ArchiveDataVO> result = getWorkerSession().findArchiveDatasFromRequestCertificate(signerid, sn, issuerdn);

            if (result.isEmpty()) {
                this.getOutputStream().println("Couldn't find any archive data from client with certificate " + certsn + " issued by " + issuerdn + " from signer " + signerid + "\n\n");
            } else {
                for(ArchiveDataVO archiveData : result) {
                    final File file = new File(outputPath, archiveData.getArchiveId() + "." + utils.getTypeName(archiveData.getType()));
                    utils.writeToFile(file, archiveData);
                    this.getOutputStream().println("Archive data with archive ID " + archiveData.getArchiveId() + " written to file : " + file);
                }
            }

            this.getOutputStream().println("\n\n");
            return 0;
        } catch (IllegalCommandArgumentsException e) {
            throw e;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
}
