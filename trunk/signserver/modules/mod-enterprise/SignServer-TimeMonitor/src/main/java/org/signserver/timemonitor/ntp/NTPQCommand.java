/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
