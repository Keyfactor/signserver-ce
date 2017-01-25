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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for the ntpdate results.
 *
 * @author Markus Kilås
 * @version $Id: NTPDateParser.java 5792 2013-09-04 11:40:45Z netmackan $
 */
public class NTPDateParser implements NTPParser {

    // server 192.168.13.200, stratum 3, offset -0.000867, delay 0.02814
    private static final String NTPDATE_PATTERN = "server ([\\d\\s.]+), stratum (\\d+), offset ([-\\d.]+), delay ([\\d.]+)";

    // message substring to look for in stderr from the ntpq command to detect
    // rate-limiting
    private static final String NTPDATE_RATELIMIT_STRING =
            "rate limit response from server";

    private final Pattern pattern = Pattern.compile(NTPDATE_PATTERN);

    /**
     * Produces an NTPDateResult given the exitValue, errorMessage and lines 
     * obtained from the ntpdate execution.
     * @param exitValue The exitValue to include in the result
     * @param errorMessage The errorMessage to include in the results
     * @param lines The output lines from the ntpdate command to parse
     * @return a new NTPDateResult with all information
     */
    @Override
    public NTPDateResult parse(int exitValue, String errorMessage, List<String> lines) {
        String server = null;
        int stratum = 16;
        double offset = Double.NaN;
        double delay = Double.NaN;
        final StringBuilder buff = new StringBuilder();
        if (errorMessage != null) {
            buff.append(errorMessage);
        }

        final boolean gotRateLimiting =
                errorMessage != null && errorMessage.indexOf(NTPDATE_RATELIMIT_STRING) != -1;
        
        if (!lines.isEmpty()) {
	    for (final String line : lines) {
		final Matcher m = pattern.matcher(line);

		if (m.matches()) {
		    server = m.group(1);
		    stratum = Integer.parseInt(m.group(2));
		    offset = Double.parseDouble(m.group(3));
		    delay = Double.parseDouble(m.group(4));

		    // ntpdate returns stratum 0 for unreachable servers
		    if (stratum > 0) {
			break;
		    } else if (stratum == 0) {
                        buff.append("Server didn't respond: ").append(line).append("\n");
		    } else {
                        buff.append("Invalid stratum value in response: ").append(line).append("\n");
		    }
		} else {
		    buff.append("Unmatched line: \"").append(line).append("\"").append("\n");
		}
	    }
        }

        return new NTPDateResult(exitValue, buff.toString(), server, stratum,
                offset, delay, gotRateLimiting);
    }

}
