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

import java.util.HashMap;
import java.util.Map;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;
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
    
    private static final String DEFAULT_PU = "cesecore-read";
    
    private EntityManager entityManager;
    
    protected EntityManager getEntityManager() throws IllegalCommandArgumentsException {
        if (entityManager == null) {
            final Map properties = new HashMap();
            properties.put("hibernate.dialect", getRequiredProperty("dbcli.hibernate.dialect"));
            properties.put("hibernate.connection.url", getRequiredProperty("dbcli.hibernate.connection.url"));
            properties.put("hibernate.connection.driver_class", getRequiredProperty("dbcli.hibernate.connection.driver_class"));
            properties.put("hibernate.connection.username", getRequiredProperty("dbcli.hibernate.connection.username"));
            properties.put("hibernate.connection.password", getRequiredProperty("dbcli.hibernate.connection.password"));

            final EntityManagerFactory amf = Persistence.createEntityManagerFactory(DEFAULT_PU, properties);
            entityManager = amf.createEntityManager();
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
