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
 * @version $Id$
 */
public class WSAuditorsCommand extends AbstractWSClientsCommand {
    
   
    private static final String USAGE =
            "Usage: signserver wsauditors -add -certserialno <certificate serial number> -issuerdn <issuer DN>\n"
    		+ "Usage: signserver wsauditors -add -cert <PEM or DER file>\n"
            + "Usage: signserver wsauditors -remove -certserialno <certificate serial number> -issuerdn <issuer DN>\n"
            + "Usage: signserver wsauditors -list\n"
            + "Example 1: signserver wsauditors -add -certserialno 0123ABCDEF -issuerdn \"CN=Neo Morpheus, C=SE\"\n"
            + "Example 2: signserver wsauditors -add -cert wsauditor.pem\n"
            + "Example 3: signserver wsauditors -remove -certserialno 0123ABCDEF -issuerdn \"CN=Neo Morpheus, C=SE\"\n"
            + "Example 4: signserver wsauditors -list";

    @Override
    public String getDescription() {
        return "Manages authorizations for WS auditors";
    }

    @Override
    public String getUsages() {
        return USAGE;
    }

    @Override
    protected String getClientsProperty() {
        return "WSAUDITORS";
    }    
}
