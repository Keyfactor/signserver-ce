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
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.signserver.common.AuthorizedClient;
import org.signserver.common.util.PropertiesApplier;
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
    
    
    public void test01Basic() throws Exception {
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
    
    public void test02RemoveWorkerProperty() throws Exception {
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
    
    public void test03SetPropertiesGenIDs() throws Exception {
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

    private static class MockPropertiesApplier extends PropertiesApplier {

        private Map<GlobalProperty, String> globalProperties = new HashMap<GlobalProperty, String>();
        private Map<WorkerProperty, String> workerProperties = new HashMap<WorkerProperty, String>();
        
        public static int FIRST_GENERATED_ID = 1000;
        
        public String getWorkerProperty(final int workerId, final String key) {
            return workerProperties.get(new WorkerProperty(Integer.toString(workerId), key));
        }
        
        public String getGlobalProperty(final String scope, final String key) {
            return globalProperties.get(new GlobalProperty(scope, key));
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
            // TODO Auto-generated method stub
            
        }

        @Override
        protected void removeAuthorizedClient(int workerId, AuthorizedClient ac) {
            // TODO Auto-generated method stub
            
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
