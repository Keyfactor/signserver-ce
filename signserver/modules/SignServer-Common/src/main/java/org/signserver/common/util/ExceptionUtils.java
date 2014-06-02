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

import java.util.LinkedList;
import java.util.List;

/**
 * Helper methods related to exception handling.
 *
 * @author Markus Kilås
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ExceptionUtils {

    /**
     * Concatenates the exception messages from all causes.
     * Duplicated messages are removed.
     *
     * @param ex Exception to print the error messages for
     * @param separator String to print between each message
     * @return String with all messages concatenated
     */
    public static String catCauses(Throwable ex, String separator) {
        final List<String> causes = new LinkedList<String>();
        Throwable cause = ex;
        while (cause != null) {
            final String causeMessage = cause.getMessage();
            if (causeMessage != null && !"null".equals(causeMessage) && !causes.contains(causeMessage)) {
                causes.add(causeMessage);
            }
            cause = cause.getCause();
        }
        final StringBuilder sb = new StringBuilder();
        for (final String causeMessage : causes) {
            if (sb.length() > 0) {
                sb.append(separator);
            }
            sb.append(causeMessage);
        }
        return sb.toString();
    }

}
