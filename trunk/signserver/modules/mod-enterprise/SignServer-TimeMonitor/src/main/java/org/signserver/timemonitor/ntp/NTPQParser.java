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

import java.util.List;

import org.apache.log4j.Logger;
import org.signserver.timemonitor.common.LeapState;

/**
 * Parser for ntpq results
 *
 * @author Marcus Lundblad
 * @version $Id: NTPQParser.java 5795 2013-09-04 12:26:51Z netmackan $
 */
public class NTPQParser implements NTPParser {

    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(NTPQParser.class);

    private String lastErrorMessage;

    @Override
    public NTPQResult parse(int exitValue, final String errorMessage, final List<String> lines) {
        // the result should be a one-line string of the form "leap=XX" (where XX is the leap status)
        if (lines.isEmpty()) {
            final String error = "No result when running the ntpq command";
            if (!error.equals(lastErrorMessage)) {
                LOG.error(error);
                lastErrorMessage = error;
            }
            return new NTPQResult(exitValue, errorMessage, LeapState.UNKNOWN);
        }

        for (final String line : lines) {
            int pos = line.indexOf("leap=");

            if (pos != -1) {
                final String restOfLine = line.substring(pos);
                // there either a "," marking the next value, or end-of-line
                int commaPos = restOfLine.indexOf(",");
                final String leapCode = restOfLine.substring("leap=".length(), commaPos == -1 ? restOfLine.length() : commaPos);

                LeapState state;

                if ("00".equals(leapCode)) {
                    state = LeapState.NONE;
                    lastErrorMessage = null;
                } else if ("01".equals(leapCode)) {
                    state = LeapState.POSITIVE;
                    lastErrorMessage = null;
                } else if ("10".equals(leapCode)) {
                    state = LeapState.NEGATIVE;
                    lastErrorMessage = null;
                } else {
                    final String error = "Unknown leap code in result when running the ntpq command: " + leapCode;
                    if (!error.equals(lastErrorMessage)) {
                        LOG.error(error);
                        lastErrorMessage = error;
                    }
                    state = LeapState.UNKNOWN;
                }

                return new NTPQResult(exitValue, errorMessage, state);
            }
        }

        LOG.error("Could not find leap code in response");
        return new NTPQResult(exitValue, errorMessage, LeapState.UNKNOWN);
    }

}
