/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.client.cli.defaultimpl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.apache.log4j.Logger;

/**
 * Helper to prompt for a key alias from a keystore.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class PromptUtils {
    private static final Logger LOG = Logger.getLogger(PromptUtils.class);

    /**
     * Prompt for selecting a key alias among a set of possible values.
     * Will present a numbered selection if more than one alias present in
     * the valid selection, otherwise a confirmation for the single one.
     * 
     * @param validAliases array of strings with aliases to select from
     * @param out PrintStream to write selection options to
     * @param heading Heading to print before listing the available aliases
     * @return The selected alias value, or null if no valid was entered within 4 tries
     */
    public static String chooseAlias(final String[] validAliases,
                                     final PrintStream out,
                                     final String heading) {
        String selectedAlias = null;
        Arrays.sort(validAliases);
        out.println(heading);
        int i = 1;
        for (String alias : validAliases) {
            out.println("[" + i++ + "] " + alias);
        }
        out.flush();
        final String format;
        if (validAliases.length > 1) {
            format = "Choose [1-%d]: ";
        } else {
            format = "Choose [%d]: ";
        }

        for (int j = 0; j < 3; j++) {
            out.printf(format, i - 1);

            final BufferedReader reader =
                    new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

            String answer = null;
            try {
                answer = reader.readLine();
            } catch (IOException ex) {
                LOG.error("Failed to read answer: " + ex);
            }

            if (answer == null) {
                break;
            }
            answer = answer.trim();
            try {
                int choice = Integer.valueOf(answer);

                if (choice > 0 && choice < i) {
                    selectedAlias = validAliases[choice - 1];
                    break;
                }

            } catch (NumberFormatException ex) {}
        }

        return selectedAlias;
    }
}
