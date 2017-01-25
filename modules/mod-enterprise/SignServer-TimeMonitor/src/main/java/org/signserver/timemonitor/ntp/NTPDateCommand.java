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

import java.util.ArrayList;
import java.util.Arrays;
import org.apache.log4j.Logger;

/**
 * Wrapper for the ntpdate command.
 *
 * @author Markus Kilås
 * @version $Id: NTPDateCommand.java 5239 2013-05-13 10:56:21Z malu9369 $
 */
public class NTPDateCommand extends AbstractCommand {

    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(NTPDateCommand.class);

    /**
     * Creates an new instance of NTPDateCommand.
     * @param executable The ntpdate command to invoke
     * @param host Host of NTP server
     */
    public NTPDateCommand(final String executable, final String host) {
        this(executable, host, null, null);
    }

    /**
     * Creates an new instance of NTPDateCommand.
     * @param executable The ntpdate command to invoke
     * @param hosts Host of NTP server (or comma-separated list)
     * @param samples Number of samples to send
     * @param timeout The timeout to use
     */
    public NTPDateCommand(final String executable, final String hosts, final Integer samples, final Double timeout) {
        if (executable == null) {
            throw new IllegalArgumentException("Executable must be specified");
        }
        if (hosts == null) {
            throw new IllegalArgumentException("Host must be specified");
        }

        final String[] splitHosts = hosts.split(",");

        parser = new NTPDateParser();

        ArrayList<String> args = new ArrayList<>();
        args.add(executable);
        args.add("-q");
        if (samples != null) {
            args.add("-p");
            args.add(String.valueOf(samples));
        }
        if (timeout != null && !Double.isNaN(timeout)) {
            args.add("-t");
            args.add(String.valueOf(timeout));
        }

        for (final String server : splitHosts) {
            args.add(server.trim());
        }

        this.arguments = args.toArray(new String[0]);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Command line: " + Arrays.toString(arguments));
        }
    }

}
