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
package org.signserver.cli.archive;

import java.io.File;
import java.io.FileOutputStream;

import org.signserver.cli.BaseCommand;
import org.signserver.cli.ErrorAdminCommandException;
import org.signserver.cli.IllegalAdminCommandException;
import org.signserver.common.ArchiveDataVO;

/**
 * Finds archivedata from database with given id.
 *
 * @version $Id$
 */
public class FindFromArchiveIdCommand extends BaseCommand {

    /**
     * Creates a new instance of FindFromArchiveIdCommand
     *
     * @param args command line arguments
     */
    public FindFromArchiveIdCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length != 5) {
            throw new IllegalAdminCommandException("Usage: signserver archive findfromarchiveid <signerid> <archiveid> <outputpath>\n"
                    + "Example: signserver archive findfromarchiveid 1 EF34242D2324 /tmp/archivedata\n\n");
        }
        try {
            int signerid = getWorkerId(args[2], hostname);
            checkThatWorkerIsProcessable(signerid, hostname);

            String archiveid = args[3];
            File outputPath = new File(args[4]);
            if (!outputPath.exists()) {
                throw new IllegalAdminCommandException("Error output path " + args[4] + " doesn't exist\n\n");
            }
            if (!outputPath.isDirectory()) {
                throw new IllegalAdminCommandException("Error output path " + args[4] + " isn't a directory\n\n");
            }

            this.getOutputStream().println("Trying to find archive data with archiveid " + archiveid + "\n");

            ArchiveDataVO result = getCommonAdminInterface(hostname).findArchiveDataFromArchiveId(signerid, archiveid);

            if (result != null) {
                String filename = outputPath.getAbsolutePath() + "/" + result.getArchiveId();
                FileOutputStream os = new FileOutputStream(filename);
                os.write(result.getArchiveData().getData());
                os.close();
                this.getOutputStream().println("Archive data with archiveid " + archiveid + " written to file : " + filename + "\n\n");
            } else {
                this.getOutputStream().println("Couldn't find any archive data with archiveid " + archiveid + " from signer " + signerid + "\n\n");
            }

            this.getOutputStream().println("\n\n");

        } catch (IllegalAdminCommandException e) {
            throw e;
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    public int getCommandType() {
        return TYPE_EXECUTEONMASTER;
    }
    // execute
}
