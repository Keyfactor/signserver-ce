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
package org.signserver.common.util;

import org.apache.log4j.Logger;
import org.signserver.server.log.AdminInfo;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A helper class that handles read-only workers.
 */
public class ReadOnlyUtils {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ReadOnlyUtils.class);

    /**
     * Checks if the requests comes from Admin CLI and if the worker is read-only or not. If the request is sent from
     * Admin CLI, we ignore the read-only worker check.
     * @param adminInfo Administrator information
     * @param workerId Worker ID
     * @return true if the request is sent from Admin CLI or if the worker is not read-only and can therefore be modified
     * by any admin.
     */
    public static boolean isModificationAllowed(final AdminInfo adminInfo, final int workerId, final Set<Integer> readOnlyWorkers) {
        if (adminInfo != null && "CLI user".equals(adminInfo.getSubject())) {
            return true;
        }
        return !readOnlyWorkers.contains(workerId);
    }

    /**
     * Parses a comma-separated string of worker ID values and ranges into a set of worker IDs.
     * @param workerIdRange a string representation of worker id value and ranges.
     * @return an unmodifiable set containing all parsed worker IDs or an empty set if no input.
     * @throws NumberFormatException if an entry or range boundary cannot be parsed as an integer.
     */
    public static Set<Integer> parseReadOnlyWorkersRange(final String workerIdRange) {
        final Set<Integer> result = new HashSet<>();
        boolean isInputValid = true;
        List<String> misconfiguredIds = new ArrayList<>();

        if (workerIdRange == null || workerIdRange.trim().isEmpty() || (workerIdRange.startsWith("${") && workerIdRange.endsWith("}"))) {
            return Collections.emptySet();
        }

        for (String workerEntry : workerIdRange.split(",")) {
            workerEntry = workerEntry.trim();
            if (workerEntry.isEmpty()) {
                continue;
            }
            try {
                if (workerEntry.contains("-")) {
                    String[] rangeParts = workerEntry.split("-",-1);
                    // rangeParts.length > 2 indicates multiple "-" characters
                    // numeric validity is checked during parsing
                    if (rangeParts.length > 2 ) {
                        throw new NumberFormatException();
                    }
                    // Exactly two parts means a valid "from-to" range
                    if (rangeParts.length == 2) {
                        int from = Integer.parseInt(rangeParts[0].trim());
                        int to = Integer.parseInt(rangeParts[1].trim());
                        for (int id = from; id <= to; id++) {
                            result.add(id);
                        }
                    }
                } else {
                    result.add(Integer.parseInt(workerEntry));
                }

            } catch (NumberFormatException ex) {
                // Invalid token (non-numeric, malformed range, or negative value)
                // is skipped and reported via logging
                misconfiguredIds.add(workerEntry);
                isInputValid = false;
            }
        }
        if (!isInputValid) {
            LOG.warn("The workerids.readonly property contains a range that cannot be parsed: " + misconfiguredIds) ;
        }
        return Collections.unmodifiableSet(result);
    }
}
