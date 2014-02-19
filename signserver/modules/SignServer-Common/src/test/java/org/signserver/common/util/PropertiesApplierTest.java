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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.signserver.common.AuthorizedClient;
import org.signserver.common.util.PropertiesApplier;
import org.signserver.common.util.PropertiesApplier.PropertiesApplierException;
import org.signserver.common.util.PropertiesConstants;
import org.signserver.common.util.PropertiesParser.GlobalProperty;
import org.signserver.common.util.PropertiesParser.WorkerProperty;

import junit.framework.TestCase;

/**
 * Tests for the property applier used for loading configuration property files.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class PropertiesApplierTest extends TestCase {
    
    final MockPropertiesApplier applier =
            new MockPropertiesApplier();
    
    /**
     * Test config setting up a worker.
     */
    private static String config1 =
            "GLOB.WORKER42.CLASSPATH = foo.bar.Worker\n" +
            "GLOB.WORKER42.SIGNERTOKEN.CLASSPATH = foo.bar.Token\n" +
            "WORKER42.NAME = TestSigner\n" +
            "WORKER42.FOOBAR = Some value\n";
    
    /**
     * Test config removing a worker property from an existing worker.
     */
    private static String config2 =
            "-WORKER42.FOOBAR = Some value";
    
    /**
     * Test config with generated IDs.
     */
    private static String config3 =
            "GLOB.WORKERGENID1.CLASSPATH = foo.bar.Worker\n" +
            "GLOB.WORKERGENID1.SIGNERTOKEN.CLASSPATH = foo.bar.Token\n" +
            "WORKERGENID1.NAME = Worker1\n" +
            "GLOB.WORKERGENID2.CLASSPATH = foo.bar.Worker\n" +
            "GLOB.WORKERGENID2.SIGNERTOKEN.CLASSPATH = foo.bar.Token\n" +
            "WORKERGENID2.NAME = Worker2\n";
    
    /**
     * Test config removing a global property.
     */
    private static String config4 =
            "-GLOB.WORKER42.CLASSPATH = foo.bar.Worker";
    
    /**
     * Test config adding auth clients.
     */
    private static String config5 =
            "WORKER42.AUTHCLIENT1 = 123456789;CN=Authorized\n" +
            "WORKER42.AUTHCLIENT2 = 987654321;CN=AlsoAuthorized";
    
    /**
     * Test config removing an authorized client.
     */
    private static String config6 =
            "-WORKER42.AUTHCLIENT1 = 123456789;CN=Authorized";
    
    /**
     * Test config with a malformed GENID.
     */
    private static String config7 =
            "GLOB.WORKERGENIDXXX.CLASSPATH = foo.bar.Worker\n" +
            "GLOB.WORKERGENIDXXX.SIGNERTOKEN.CLASSPATH = foo.bar.Token\n" +
            "WORKERGENIDXXX.NAME = Worker3";
    
    public void testBasic() throws Exception {
        final PropertiesParser parser = new PropertiesParser();
        
        final Properties prop = new Properties();
        
        try {
            prop.load(new ByteArrayInputStream(config1.getBytes()));
            parser.process(prop);
            applier.apply(parser);
            
            assertEquals("Has set global property", "foo.bar.Worker",
                    applier.getGlobalProperty(PropertiesConstants.GLOBAL_PREFIX_DOT,
                            "WORKER42.CLASSPATH"));
            assertEquals("Has set global property", "foo.bar.Token",
                    applier.getGlobalProperty(PropertiesConstants.GLOBAL_PREFIX_DOT,
                            "WORKER42.SIGNERTOKEN.CLASSPATH"));
            assertEquals("Has set worker property", "TestSigner",
                    applier.getWorkerProperty(42, "NAME"));
            assertEquals("Has set worker property", "Some value",
                    applier.getWorkerProperty(42, "FOOBAR"));
            
        } catch (IOException e) {
            fail("Failed to parse properties: " + e.getMessage());
        }
        
    }
    
    public void testRemoveWorkerProperty() throws Exception {
        final PropertiesParser parser = new PropertiesParser();
        
        final Properties prop = new Properties();
        
        try {
            prop.load(new ByteArrayInputStream(config2.getBytes()));
            parser.process(prop);
            applier.apply(parser);
            
            assertNull("Should have remove worker property",
                    applier.getWorkerProperty(42, "FOOBAR"));
        } catch (IOException e) {
            fail("Failed to parse properties: " + e.getMessage());
        }
    }
    
    public void testSetPropertiesGenIDs() throws Exception {
        final PropertiesParser parser = new PropertiesParser();
        
        final Properties prop = new Properties();
        
        try {
            prop.load(new ByteArrayInputStream(config3.getBytes()));
            parser.process(prop);
            applier.apply(parser);
            
            assertEquals("Set worker name for generated ID", "Worker1", applier.getWorkerProperty(1000, "NAME"));
            assertEquals("Set worker name for generated ID", "Worker2", applier.getWorkerProperty(1001, "NAME"));
            
        } catch (IOException e) {
            fail("Failed to parse properties: " + e.getMessage());
        }
    }

    public void testRemoveGlobalProperty() throws Exception {
        final PropertiesParser parser = new PropertiesParser();
        
        final Properties prop = new Properties();
        
        try {
            prop.load(new ByteArrayInputStream(config4.getBytes()));
            parser.process(prop);
            applier.apply(parser);
            
            assertNull("Removed global property",
                    applier.getGlobalProperty(PropertiesConstants.GLOBAL_PREFIX_DOT, "WORKER42.CLASSPATH"));
        } catch (IOException e) {
            fail("Failed to parse properties: " + e.getMessage());
        }
    }
    
    public void testAddRemoveAuthClients() throws Exception {
        PropertiesParser parser;
        
        final Properties prop = new Properties();
        
        try {
            parser = new PropertiesParser();
            prop.load(new ByteArrayInputStream(config5.getBytes()));
            parser.process(prop);
            applier.apply(parser);
            
            assertTrue("Authorized client", applier.isAuthorized(42, new AuthorizedClient("123456789", "CN=Authorized")));
            assertTrue("Authorized client", applier.isAuthorized(42, new AuthorizedClient("987654321", "CN=AlsoAuthorized")));
            
            parser = new PropertiesParser();
            prop.clear();
            prop.load(new ByteArrayInputStream(config6.getBytes()));
            parser.process(prop);
            applier.apply(parser);
            
            assertFalse("Not authorized", applier.isAuthorized(42, new AuthorizedClient("123456789", "CN=Authorized")));
            assertTrue("Authorized client", applier.isAuthorized(42, new AuthorizedClient("987654321", "CN=AlsoAuthorized")));
        } catch (IOException e) {
            fail("Failed to parse properties: " + e.getMessage());
        }
    }
    
    public void testMalformedGenID() throws Exception {
        final PropertiesParser parser = new PropertiesParser();
        
        final Properties prop = new Properties();
        
        try {
            prop.load(new ByteArrayInputStream(config7.getBytes()));
            parser.process(prop);
            applier.apply(parser);
            
            assertEquals("Error message", "Illegal generated ID: GENIDXXX",
                    applier.getError());
        } catch (IOException e) {
            fail("Failed to parse properties: " + e.getMessage());
        } 
    }
    
    private static class MockPropertiesApplier extends PropertiesApplier {

        private Map<GlobalProperty, String> globalProperties = new HashMap<GlobalProperty, String>();
        private Map<WorkerProperty, String> workerProperties = new HashMap<WorkerProperty, String>();
        private Map<Integer, Set<AuthorizedClient>> authClients = new HashMap<Integer, Set<AuthorizedClient>>();
        
        public static int FIRST_GENERATED_ID = 1000;
        
        public String getWorkerProperty(final int workerId, final String key) {
            return workerProperties.get(new WorkerProperty(Integer.toString(workerId), key));
        }
        
        public String getGlobalProperty(final String scope, final String key) {
            return globalProperties.get(new GlobalProperty(scope, key));
        }
        
        public boolean isAuthorized(final int workerId, final AuthorizedClient ac) {
            final Set<AuthorizedClient> acs = authClients.get(workerId);
            
            if (acs != null) {
                return acs.contains(ac);
            }
            
            return false;
        }
        
        @Override
        protected void setGlobalProperty(String scope, String key, String value) {
            globalProperties.put(new GlobalProperty(scope, key), value);
        }

        @Override
        protected void removeGlobalProperty(String scope, String key) {
            globalProperties.remove(new GlobalProperty(scope, key));
        }

        @Override
        protected void setWorkerProperty(int workerId, String key, String value) {
            workerProperties.put(new WorkerProperty(Integer.toString(workerId), key), value);
        }

        @Override
        protected void removeWorkerProperty(int workerId, String key) {
            workerProperties.remove(new WorkerProperty(Integer.toString(workerId), key));
        }

        @Override
        protected void uploadSignerCertificate(int workerId, byte[] signerCert) {
            // TODO Auto-generated method stub
            
        }

        @Override
        protected void uploadSignerCertificateChain(int workerId,
                List<byte[]> signerCertChain) {
            // TODO Auto-generated method stub
            
        }

        @Override
        protected void addAuthorizedClient(int workerId, AuthorizedClient ac) {
            Set<AuthorizedClient> acs = authClients.get(workerId);
            
            if (acs == null) {
                acs = new HashSet<AuthorizedClient>();
                authClients.put(workerId, acs);
            }
            
            acs.add(ac);
        }

        @Override
        protected void removeAuthorizedClient(int workerId, AuthorizedClient ac) {
            final Set<AuthorizedClient> acs = authClients.get(workerId);
            
            if (acs != null) {
                acs.remove(ac);
            }
        }

        @Override
        protected int genFreeWorkerId() throws PropertiesApplierException {
            return FIRST_GENERATED_ID;
        }

        @Override
        protected int getWorkerId(String workerName)
                throws PropertiesApplierException {
            for (final WorkerProperty prop : workerProperties.keySet()) {
                if (PropertiesConstants.NAME.equals(prop.getKey())) {
                    final String value = workerProperties.get(prop);
                    
                    if (workerName.equals(value)) {
                        return Integer.valueOf(prop.getWorkerIdOrName());
                    }
                }
            }
            
            throw new PropertiesApplierException("No such worker: " + workerName);
        }
        
    }
    
}
