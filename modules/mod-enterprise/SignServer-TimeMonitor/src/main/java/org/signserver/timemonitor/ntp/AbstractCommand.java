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
package org.signserver.timemonitor.ntp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.LinkedList;
import java.util.List;

import org.apache.log4j.Logger;

/**
 * Base class for running NTP commands
 *
 * @author Marcus Lundblad
 * @version $Id: AbstractCommand.java 5862 2013-09-16 08:12:56Z netmackan $
 *
 */

public abstract class AbstractCommand {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(AbstractCommand.class);

    protected String[] arguments;

    protected NTPParser parser;

    /**
     * Execute the ntpdate command.
     *
     * @return The results.
     * @throws IOException In case of IO errors.
     */
    public AbstractResult execute() throws IOException {
        Process proc;
        BufferedReader stdIn = null;
        BufferedReader errIn = null;
        OutputStream stdOut = null;

        try {
            Runtime runtime = Runtime.getRuntime();

            proc = runtime.exec(arguments);
            stdIn = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            errIn = new BufferedReader(new InputStreamReader(proc.getErrorStream()));
            stdOut = proc.getOutputStream();

            List<String> lines = new LinkedList<>();
            String line;
            while ((line = stdIn.readLine()) != null) {
                lines.add(line);
            }

            StringBuilder errBuff = new StringBuilder();
            while ((line = errIn.readLine()) != null) {
                errBuff.append(line).append("\n");
            }
            try {
                proc.waitFor();
                return parser.parse(proc.exitValue(), errBuff.toString(), lines);
            } catch (InterruptedException ex) {
                LOG.error("Command interrupted", ex);
                return parser.parse(-1, errBuff.toString(), lines);
            }
        } finally {
            if (stdOut != null) {
                try {
                    stdOut.close();
                } catch (IOException ignored) {} // NOPMD
            }
            if (stdIn != null) {
                try {
                    stdIn.close();
                } catch (IOException ignored) {} // NOPMD
            }
            if (errIn != null) {
                try {
                    errIn.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }

    /**
     * @return The command and arguments to the ntpdate command
     */
    public String[] getArguments() {
        return arguments;
    }

}
