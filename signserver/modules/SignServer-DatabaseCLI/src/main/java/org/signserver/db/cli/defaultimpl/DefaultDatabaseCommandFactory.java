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
package org.signserver.db.cli.defaultimpl;

import org.signserver.cli.spi.AbstractCommandFactory;
import org.signserver.db.cli.defaultimpl.audit.VerifyLogCommand;
import org.signserver.db.cli.spi.DatabaseCommandFactory;


/**
 * CommandFactory for the default database commands used by the Database CLI.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class DefaultDatabaseCommandFactory extends AbstractCommandFactory implements DatabaseCommandFactory {

    @Override
    protected void registerCommands() {
        // Top level commands
        
        // Audit commands
        put("audit", "verifylog", VerifyLogCommand.class);
    }

}
