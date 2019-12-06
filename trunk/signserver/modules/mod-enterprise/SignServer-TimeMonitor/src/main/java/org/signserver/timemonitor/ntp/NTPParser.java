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

import java.util.List;

/**
 * Interface defining parsers for the result of NTP-related CLI commands.
 *
 * @author Marcus Lundblad
 * @version $Id: NTPParser.java 4508 2012-12-05 08:09:52Z marcus $
 *
 */
public interface NTPParser {

    /**
     * Produces an AbstractResult instance given the exitValue, errorMessage and lines 
     * obtained from the ntp commands execution.
     * @param exitValue The exitValue to include in the result
     * @param errorMessage The errorMessage to include in the results
     * @param lines The output lines from the ntpdate command to parse
     * @return a new NTPDateResult with all information
     */
    public AbstractResult parse(int exitValue, String errorMessage, List<String> lines);
}
