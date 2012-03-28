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
import org.signserver.admin.cli.defaultimpl.AdminCommandHelper;
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.ArchiveDataVO;

/**
 * Finds archivedata from database with given id.
 *
 * @version $Id$
 */
public class FindFromArchiveIdCommand extends AbstractCommand {

    private AdminCommandHelper helper = new AdminCommandHelper();

    @Override
    public String getDescription() {
        return "Find archivables matching an archive id";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver archive findfromarchiveid <signerid> <archiveid> <outputpath>\n"
                    + "Example: signserver archive findfromarchiveid 1 EF34242D2324 /tmp/archivedata\n\n";
    }
    
    @Override
    public int execute(String[] args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 3) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        try {
            int signerid = helper.getWorkerId(args[0]);
            helper.checkThatWorkerIsProcessable(signerid);

            String archiveid = args[1];
            File outputPath = new File(args[2]);
            if (!outputPath.exists()) {
                throw new IllegalCommandArgumentsException("Error output path " + args[2] + " doesn't exist\n\n");
            }
            if (!outputPath.isDirectory()) {
                throw new IllegalCommandArgumentsException("Error output path " + args[2] + " isn't a directory\n\n");
            }

            out.println("Trying to find archive data with archiveid " + archiveid + "\n");

            ArchiveDataVO result = helper.getWorkerSession().findArchiveDataFromArchiveId(signerid, archiveid);

            if (result != null) {
                String filename = outputPath.getAbsolutePath() + "/" + result.getArchiveId();
                FileOutputStream os = new FileOutputStream(filename);
                os.write(result.getArchivedBytes());
                os.close();
                out.println("Archive data with archiveid " + archiveid + " written to file : " + filename + "\n\n");
            } else {
                out.println("Couldn't find any archive data with archiveid " + archiveid + " from signer " + signerid + "\n\n");
            }

            out.println("\n\n");
            return 0;

        } catch (IllegalCommandArgumentsException e) {
            throw e;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }

}
