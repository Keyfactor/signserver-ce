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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.SharedCacheMode;
import javax.persistence.ValidationMode;
import javax.persistence.spi.ClassTransformer;
import javax.persistence.spi.PersistenceUnitInfo;
import javax.persistence.spi.PersistenceUnitTransactionType;
import javax.sql.DataSource;
import static org.hibernate.cfg.AvailableSettings.DIALECT;
import static org.hibernate.cfg.AvailableSettings.GENERATE_STATISTICS;
import static org.hibernate.cfg.AvailableSettings.HBM2DDL_AUTO;
import static org.hibernate.cfg.AvailableSettings.JPA_JDBC_DRIVER;
import static org.hibernate.cfg.AvailableSettings.JPA_JDBC_PASSWORD;
import static org.hibernate.cfg.AvailableSettings.JPA_JDBC_URL;
import static org.hibernate.cfg.AvailableSettings.JPA_JDBC_USER;
import static org.hibernate.cfg.AvailableSettings.JPA_QUERY_COMPLIANCE;
import static org.hibernate.cfg.AvailableSettings.QUERY_STARTUP_CHECKING;
import static org.hibernate.cfg.AvailableSettings.SHOW_SQL;
import static org.hibernate.cfg.AvailableSettings.USE_QUERY_CACHE;
import static org.hibernate.cfg.AvailableSettings.USE_REFLECTION_OPTIMIZER;
import static org.hibernate.cfg.AvailableSettings.USE_SECOND_LEVEL_CACHE;
import static org.hibernate.cfg.AvailableSettings.USE_STRUCTURED_CACHE;
import org.hibernate.jpa.HibernatePersistenceProvider;
import org.signserver.cli.spi.IllegalCommandArgumentsException;

/**
 * Helper methods for setting up an entity manager based on configuration 
 * properties.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class DatabaseHelper {

    private static final String HSQLDB = "hsqldb";
    private static final String MYSQL = "mysql";
    private static final String ORACLE = "oracle";
    private static final String POSTGRES = "postgres";
    
    private static final HashSet<String> types = new HashSet<>();
    private static final HashMap<String, String> DIALECTS = new HashMap<>();
    private static final HashMap<String, String> DRIVERS = new HashMap<>();
    
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
    
    public EntityManager getEntityManager(final String dbType, String driverClassString, final String dbUrl, final String dbUsername, final String dbPassword) throws IllegalCommandArgumentsException {
        final EntityManager result;
        
        Class dialectClass = null;
        final String dialectClassString = DIALECTS.get(dbType);
        try {
            dialectClass = Class.forName(dialectClassString);
        } catch (ClassNotFoundException ex) {
            throw new IllegalCommandArgumentsException("Failure loading the dialect class " + ex.getMessage());
        }
        
        if (driverClassString == null) {
            driverClassString = DRIVERS.get(dbType);
        }

        final String mappingFile = "META-INF/cesecore-orm-" + dbType + ".xml";

        HashMap<String, Object> map = new HashMap();
        map.put(JPA_JDBC_DRIVER, driverClassString);
        map.put(JPA_JDBC_URL, dbUrl);
        map.put(DIALECT, dialectClass);
        map.put(HBM2DDL_AUTO, "validate");
        map.put(SHOW_SQL, false);
        map.put(QUERY_STARTUP_CHECKING, false);
        map.put(GENERATE_STATISTICS, false);
        map.put(USE_REFLECTION_OPTIMIZER, false);
        map.put(USE_SECOND_LEVEL_CACHE, false);
        map.put(USE_QUERY_CACHE, false);
        map.put(USE_STRUCTURED_CACHE, false);
        map.put(JPA_QUERY_COMPLIANCE, true);
        map.put(JPA_JDBC_USER, dbUsername);
        map.put(JPA_JDBC_PASSWORD, dbPassword);

        final EntityManagerFactory emf = new HibernatePersistenceProvider().createContainerEntityManagerFactory(
                archiverPersistenceUnitInfo(mappingFile), map);        
        result = emf.createEntityManager();

        return result;
    }
    
    private static PersistenceUnitInfo archiverPersistenceUnitInfo(String mappingFile) {
        return new PersistenceUnitInfo() {
            @Override
            public String getPersistenceUnitName() {
                return "ApplicationPersistenceUnit";
            }

            @Override
            public String getPersistenceProviderClassName() {
                return "org.hibernate.jpa.HibernatePersistenceProvider";
            }

            @Override
            public PersistenceUnitTransactionType getTransactionType() {
                return PersistenceUnitTransactionType.RESOURCE_LOCAL;
            }

            @Override
            public DataSource getJtaDataSource() {
                return null;
            }

            @Override
            public DataSource getNonJtaDataSource() {
                return null;
            }

            @Override
            public List<String> getMappingFileNames() {
                return Arrays.asList(mappingFile);
            }

            @Override
            public List<URL> getJarFileUrls() {
                try {
                    return Collections.list(this.getClass()
                            .getClassLoader()
                            .getResources(""));
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }

            @Override
            public URL getPersistenceUnitRootUrl() {
                return null;
            }

            @Override
            public List<String> getManagedClassNames() {
                return Arrays.asList("org.cesecore.audit.impl.integrityprotected.AuditRecordData");
            }

            @Override
            public boolean excludeUnlistedClasses() {
                return true;
            }

            @Override
            public SharedCacheMode getSharedCacheMode() {
                return null;
            }

            @Override
            public ValidationMode getValidationMode() {
                return null;
            }

            @Override
            public Properties getProperties() {
                return new Properties();
            }

            @Override
            public String getPersistenceXMLSchemaVersion() {
                return null;
            }

            @Override
            public ClassLoader getClassLoader() {
                return null;
            }

            @Override
            public void addTransformer(ClassTransformer transformer) {

            }

            @Override
            public ClassLoader getNewTempClassLoader() {
                return null;
            }
        };
    }

    public Set<String> getTypes() {
        return Collections.unmodifiableSet(types);
    }
    
}
