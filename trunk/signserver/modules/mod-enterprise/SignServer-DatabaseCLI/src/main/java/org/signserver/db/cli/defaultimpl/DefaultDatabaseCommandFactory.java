/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
