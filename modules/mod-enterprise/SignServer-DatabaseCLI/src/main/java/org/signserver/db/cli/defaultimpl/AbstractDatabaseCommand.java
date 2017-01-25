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

import javax.persistence.EntityManager;
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.IllegalCommandArgumentsException;

/**
 * Implements functionality for accessing the database that can be used by 
 * Commands implementing this class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class AbstractDatabaseCommand extends AbstractCommand {
    
    private final DatabaseHelper helper = new DatabaseHelper();
    private EntityManager entityManager;
    
    protected EntityManager getEntityManager() throws IllegalCommandArgumentsException {
        if (entityManager == null) {
            final String type = getRequiredProperty("dbcli.database.name");
            if (type == null) {
                throw new IllegalCommandArgumentsException("Unknown value for dbcli.database.name. Possible values are" + helper.getTypes());
            }
            
            entityManager = helper.getEntityManager(type, getConfiguration().getProperty("dbcli.database.driver"), getRequiredProperty("dbcli.database.url"), getRequiredProperty("dbcli.database.username"), getConfiguration().getProperty("dbcli.database.password", ""));
        }
        return entityManager;
    }
    
    private String getRequiredProperty(final String property) throws IllegalCommandArgumentsException {
        final String result = getConfiguration().getProperty(property);
        if (result == null || result.trim().isEmpty()) {
            throw new IllegalCommandArgumentsException("Missing required configuration property: " + property);
        }
        return result.trim();
    }
}
