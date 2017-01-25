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


/**
 * Wrapper for the ntpq command.
 *
 * @author Marcus Lundblad
 * @version $Id: NTPQCommand.java 4519 2012-12-06 10:34:48Z marcus $
 *
 */

public class NTPQCommand extends AbstractCommand {

    public NTPQCommand(final String executable, int assocId) {
        ArrayList<String> args = new ArrayList<>();

        parser = new NTPQParser();

        args.add(executable);
        args.add("-c");

        final String rvCommand = "rv " + assocId + " leap";
        args.add(rvCommand);

        arguments = args.toArray(new String[0]);
    }

}
