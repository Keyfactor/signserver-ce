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
import java.util.HashSet;
import java.util.Properties;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import org.hibernate.ejb.Ejb3Configuration;
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
    
    private static final String HSQLDB = "hsqldb";
    private static final String MYSQL = "mysql";
    private static final String ORACLE = "oracle";
    private static final String POSTGRES = "postgres";
    
    private static final HashSet<String> types = new HashSet<String>();
    private static final HashMap<String, String> DIALECTS = new HashMap<String, String>();
    private static final HashMap<String, String> DRIVERS = new HashMap<String, String>();
    
    static {
        types.add(HSQLDB);
        types.add(MYSQL);
        types.add(ORACLE);
        types.add(POSTGRES);
        
        DIALECTS.put(HSQLDB, "org.hibernate.dialect.HSQLDialect");
        DIALECTS.put(MYSQL, "org.hibernate.dialect.MySQLDialect");
        DIALECTS.put(ORACLE, "org.hibernate.dialect.Oracle10gDialect");
        DIALECTS.put(POSTGRES, "org.hibernate.dialect.PostgreSQLDialect");
        
        DRIVERS.put(HSQLDB, "org.hsqldb.jdbcDriver");
        DRIVERS.put(MYSQL, "com.mysql.jdbc.Driver");
        DRIVERS.put(ORACLE, "oracle.jdbc.driver.OracleDriver");
        DRIVERS.put(POSTGRES, "org.postgresql.Driver");
    }
    
    
    protected EntityManager getEntityManager() throws IllegalCommandArgumentsException {
        if (entityManager == null) {
            final String type = getRequiredProperty("dbcli.database.name");
            if (type == null) {
                throw new IllegalCommandArgumentsException("Unknown value for dbcli.database.name. Possible values are" + types);
            }
            
            final String dialect = DIALECTS.get(type);
            final String driverClass = DRIVERS.get(type);
            final String mappingFile = "META-INF/cesecore-orm-" + type + ".xml";
            
            // Properties to override
            Properties properties = new Properties();
            properties.put("hibernate.dialect", dialect);
            // Would have been great if we could do: properties.put("hibernate.PROPERTY-TO-SET-MAPPING-FILE", "META-INF/cesecore-orm-mysql.xml");
            properties.put("hibernate.connection.url", getRequiredProperty("dbcli.database.url"));
            properties.put("hibernate.connection.driver_class", driverClass);
            properties.put("hibernate.connection.username", getRequiredProperty("dbcli.database.username"));
            properties.put("hibernate.connection.password", getConfiguration().getProperty("dbcli.database.password", ""));

            // Explicitly use Hibernate to get the entity manager factory as we 
            // must supply an entity mappings-file at runtime
            final Ejb3Configuration cfg = new Ejb3Configuration()
                    .addResource(mappingFile)
                    .configure(DEFAULT_PU, properties);
            // Would have been nice: final EntityManagerFactory amf = Persistence.createEntityManagerFactory(DEFAULT_PU, properties);
            final EntityManagerFactory emf = cfg.buildEntityManagerFactory();
            entityManager = emf.createEntityManager();
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
