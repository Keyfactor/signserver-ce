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
package org.signserver.admin.common.config;

/**
 * Utility methods useful in the rekeying process.
 *
 * @version $Id$
 */
public class RekeyUtil {
    
    public static String nextAliasInSequence(final String currentAlias) {
        String prefix = currentAlias;
        String nextSequence = "2";

        final String[] entry = currentAlias.split("[0-9]+$");
        if (entry.length == 1) {
            prefix = entry[0];
            final String currentSequence
                    = currentAlias.substring(prefix.length());
            final int sequenceChars = currentSequence.length();
            if (sequenceChars > 0) {
                final long nextSequenceNumber = Long.parseLong(currentSequence) + 1;
                final String nextSequenceNumberString
                        = String.valueOf(nextSequenceNumber);
                if (sequenceChars > nextSequenceNumberString.length()) {
                    nextSequence = currentSequence.substring(0,
                            sequenceChars - nextSequenceNumberString.length())
                            + nextSequenceNumberString;
                } else {
                    nextSequence = nextSequenceNumberString;
                }
            }
        }

        return prefix + nextSequence;
    }
}
