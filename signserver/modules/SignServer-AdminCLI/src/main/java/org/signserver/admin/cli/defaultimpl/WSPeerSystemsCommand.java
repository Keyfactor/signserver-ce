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
package org.signserver.admin.cli.defaultimpl;

/**
 * Command for managing the list of authorized WS auditors.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class WSPeerSystemsCommand extends AbstractWSClientsCommand {
    
    private static final String USAGE =
            "Usage: signserver wspeersystems -add -certserialno <certificate serial number (in hex)> -issuerdn <issuer DN>\n"
                + "Usage: signserver wspeersystems -add -cert <PEM or DER file>\n"
            + "Usage: signserver wspeersystems -remove -certserialno <certificate serial number (in hex)> -issuerdn <issuer DN>\n"
            + "Usage: signserver wspeersystems -list\n"
            + "Example 1: signserver wspeersystems -add -certserialno 123ABCDEF -issuerdn \"CN=Neo Morpheus, C=SE\"\n"
            + "Example 2: signserver wspeersystems -add -cert wsauditor.pem\n"
            + "Example 3: signserver wspeersystems -remove -certserialno 123ABCDEF -issuerdn \"CN=Neo Morpheus, C=SE\"\n"
            + "Example 4: signserver wspeersystems -list";

    @Override
    public String getDescription() {
        return "Manages authorizations for peer systems";
    }

    @Override
    public String getUsages() {
        return USAGE;
    }

    @Override
    protected String getClientsProperty() {
        return "WSPEERS";
    }
}
