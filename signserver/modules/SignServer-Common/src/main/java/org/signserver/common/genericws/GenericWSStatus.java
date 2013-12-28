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
package org.signserver.common.genericws;

import java.io.PrintStream;
import java.util.Collections;
import java.util.Enumeration;
import org.signserver.common.CryptoTokenStatus;
import org.signserver.common.WorkerConfig;

/**
 * Class used to display the status of a ValidationService such as 
 * if the connection to the underlying services are OK.
 *
 * @author Philip Vendil
 * @version $Id$
 */
public class GenericWSStatus extends CryptoTokenStatus {

    public static final String CONNECTION_OK = "CONNECTION_OK";
    public static final String CONNECTION_FAILED = "CONNECTION_FAILED";
    private static final long serialVersionUID = 1L;

    public GenericWSStatus(int workerId, int tokenStatus, WorkerConfig config) {
        super(workerId, tokenStatus, Collections.<String>emptyList(), config);
    }

    @Override
    public void displayStatus(int workerId, PrintStream out, boolean complete) {
        out.println("Status of Generic WS with Id " + workerId
                + " (" + getActiveSignerConfig().getProperty("NAME") + ") is :\n"
                + "  SignToken Status : " + signTokenStatuses[getTokenStatus()] + " \n\n");

        if (complete) {
            out.println("Active Properties are :");

            if (getActiveSignerConfig().getProperties().size() == 0) {
                out.println("  No properties exists in active configuration\n");
            }

            Enumeration<?> propertyKeys = getActiveSignerConfig().getProperties().keys();
            while (propertyKeys.hasMoreElements()) {
                String key = (String) propertyKeys.nextElement();
                out.println("  " + key + "=" + getActiveSignerConfig().getProperties().getProperty(key) + "\n");
            }
            out.println("\n");
        }
    }
}
