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
package org.signserver.common;

import java.io.PrintStream;
import java.util.List;
import org.signserver.common.WorkerStatusInfo.Entry;

/**
 * WorkerStatus that renders the static information from the supplied
 * WorkerStatusInfo object.
 *
 * This wrapper is useful until the API is changed so that a WorkerStatusInfo
 * object can be returned directly instead and the client application will be
 * responsible for rendering the information.
 *
 * TODO: Eventually this class should be removed and the WorkerStatusInfo (or
 * similar) should be used directly instead. It is only here now to not break
 * the existing APIs too much.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class StaticWorkerStatus extends WorkerStatus {

    private final WorkerStatusInfo info;

    public StaticWorkerStatus(WorkerStatusInfo info) {
        super(info.getWorkerId(), info.getFatalErrors(), info.getWorkerConfig());
        this.info = info;
    }

    @Override
    public void displayStatus(int workerId, PrintStream out, boolean complete) {
        final List<String> errors = getFatalErrors();

        // Title
        out.println("Status of " + info.getWorkerType() + " with Id " + workerId + " (" + info.getWorkerName() + ") is :");

        // Brief statuses
        int keyWidth = maxWidth(14, info.getBriefEntries());
        final String format = "  %-" + keyWidth + "s: %s\n";
        for (Entry entry : info.getBriefEntries()) {
            if (entry.getTitle().isEmpty()) {
                out.print("  ");
                out.println(entry.getValue());
            } else {
                out.printf(format, entry.getTitle(), entry.getValue());
            }
        }
        out.println();

        // Errors
        if (errors != null && !errors.isEmpty()) {
            out.println("  Errors: ");
            for (String error : errors) {
                out.print("    ");
                out.println(error);
            }
        }
        out.println("\n\n");

        if (complete) {

            // Complete statuses
            for (Entry entry : info.getCompleteEntries()) {
                out.print(entry.getTitle());
                out.println(":");
                out.println(entry.getValue()); // TODO Indent
                out.println();
            }
        }
    }

    /**
     * Searches through the entries and takes out the maximum width of the
     * titles.
     * @param min value to use
     * @param entries to search through
     * @return the maximum length of the titles and the min value
     */
    private static int maxWidth(int min, List<Entry> entries) {
        int result = min;
        for (Entry entry : entries) {
            final int length = entry.getTitle().length();
            if (length > result) {
                result = length;
            }
        }
        return result;
    }

    /**
     * @return the token status
     */
    public int getTokenStatus() {
        return info.getTokenStatus();
    }

}
