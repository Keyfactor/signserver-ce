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
package org.signserver.server;

import java.util.Properties;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.junit.Test;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.CryptoTokenStatus;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.ResyncException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.server.cryptotokens.NullCryptoToken;
import org.signserver.server.signers.BaseSigner;

/**
 * Tests for the BaseProcessable class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class BaseProcessableTest extends TestCase {

    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(BaseProcessableTest.class);
    
    private final int workerId = 100;
    private final WorkerContext anyContext = new SignServerContext(null, null);
    
    /** Tests the base case were no default properties are used to configure the PKCS11CryptoToken. */
    @Test
    public void testGetCryptoToken_noDefaults() throws Exception {
        LOG.info("testGetCryptoToken_noDefaults");
        
        Properties globalConfig = new Properties();
        WorkerConfig workerConfig = new WorkerConfig();
        
        // Exercising all properties (except SLOTLISTINDEX)
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", MockedCryptoToken.class.getName());
        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("SHAREDLIBRARY", "/opt/hsm/pkcs11.so");
        workerConfig.setProperty("SLOT", "3");
        workerConfig.setProperty("ATTRIBUTESFILE", "/opt/hsm/sunpkcs11.cfg");
        
        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        MockedCryptoToken actualToken = (MockedCryptoToken) instance.getCryptoToken();
        Properties actualProperties = actualToken.getProps();
        
        assertEquals("same as worker config", workerConfig.getProperties().toString(), actualProperties.toString());
        
        // Exercising all properties (except SLOT)
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", MockedCryptoToken.class.getName());
        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("SHAREDLIBRARY", "/opt/hsm/pkcs11.so");
        workerConfig.setProperty("SLOTLISTINDEX", "2");
        workerConfig.setProperty("ATTRIBUTESFILE", "/opt/hsm/sunpkcs11.cfg");
        
        instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        actualToken = (MockedCryptoToken) instance.getCryptoToken();
        actualProperties = actualToken.getProps();
        
        assertEquals("same as worker config", workerConfig.getProperties().toString(), actualProperties.toString());
    }
    
    /** 
     * Test default value for SLOTLISTINDEX. 
     * First the value is specified only as a default value and then the value 
     * is overriden by the worker.
     */
    @Test
    public void testGetCryptoToken_defaultSlotListIndex() throws Exception {
        LOG.info("testGetCryptoToken_defaultSlotListIndex");
        
        Properties globalConfig = new Properties();
        WorkerConfig workerConfig = new WorkerConfig();
        
        // SLOTLISTINDEX only in GlobalConfiguration
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", MockedCryptoToken.class.getName());
        globalConfig.setProperty("GLOB.DEFAULT.SLOTLISTINDEX", "33");
        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("ATTRIBUTESFILE", "/opt/hsm/sunpkcs11.cfg");
        
        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        MockedCryptoToken actualToken = (MockedCryptoToken) instance.getCryptoToken();
        Properties actualProperties = actualToken.getProps();
        
        Properties expectedProperties = new Properties(workerConfig.getProperties());
        expectedProperties.putAll(workerConfig.getProperties());
        expectedProperties.setProperty("SLOTLISTINDEX", "33");
        assertEquals("default SLOTLISTINDEX used", 
                expectedProperties.toString(), actualProperties.toString());
        
        // SLOTLISTINDEX both in GlobalConfiguration and in Worker Config
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", MockedCryptoToken.class.getName());
        globalConfig.setProperty("GLOB.DEFAULT.SLOTLISTINDEX", "33");
        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("SHAREDLIBRARY", "/opt/hsm/pkcs11.so");
        workerConfig.setProperty("SLOTLISTINDEX", "44");
        workerConfig.setProperty("ATTRIBUTESFILE", "/opt/hsm/sunpkcs11.cfg");
        
        instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        actualToken = (MockedCryptoToken) instance.getCryptoToken();
        actualProperties = actualToken.getProps();
        
        expectedProperties = new Properties();
        expectedProperties.putAll(workerConfig.getProperties());
        expectedProperties.setProperty("SLOTLISTINDEX", "44");
        assertEquals("worker overriding SLOTLISTINDEX used", 
                expectedProperties.toString(), actualProperties.toString());
    }
    
    /**
     * Test default values for all PKCS11CryptoToken properties that can have
     * default values.
     * First the values are only specified as default values and then they are
     * overriden by the worker.
     * The SLOTLISTINDEX property is not specified here as it should not be 
     * specified at the same time as the SLOT property and it is also tested in 
     * a separate test.
     */
    @Test
    public void testGetCryptoToken_defaultAll() throws Exception {
        LOG.info("testGetCryptoToken_defaultAll");
        
        Properties globalConfig = new Properties();
        WorkerConfig workerConfig = new WorkerConfig();
        
        // All PKCS#11 properties that can have default values in GlobalConfiguration (except SLOTLISTINDEX)
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", MockedCryptoToken.class.getName());
        globalConfig.setProperty("GLOB.DEFAULT.SHAREDLIBRARY", "/opt/hsm/default-pkcs11.so");
        globalConfig.setProperty("GLOB.DEFAULT.SLOT", "44");
        globalConfig.setProperty("GLOB.DEFAULT.ATTRIBUTESFILE", "/opt/hsm/default-sunpkcs11.cfg");
        workerConfig.setProperty("NAME", "TestSigner100");
        
        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        MockedCryptoToken actualToken = (MockedCryptoToken) instance.getCryptoToken();
        Properties actualProperties = actualToken.getProps();
        
        Properties expectedProperties = new Properties();
        expectedProperties.putAll(workerConfig.getProperties());
        expectedProperties.setProperty("SHAREDLIBRARY", "/opt/hsm/default-pkcs11.so");
        expectedProperties.setProperty("SLOT", "44");
        expectedProperties.setProperty("ATTRIBUTESFILE", "/opt/hsm/default-sunpkcs11.cfg");
        assertEquals("default SHAREDLIBRARY etc used", 
                expectedProperties.toString(), actualProperties.toString());
        
        // All PKCS#11 properties that can have default values GlobalConfiguration and overriden in Worker Config (except SLOTLISTINDEX)
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", MockedCryptoToken.class.getName());
        globalConfig.setProperty("GLOB.DEFAULT.SHAREDLIBRARY", "/opt/hsm/default-pkcs11.so");
        globalConfig.setProperty("GLOB.DEFAULT.SLOT", "44");
        globalConfig.setProperty("GLOB.DEFAULT.ATTRIBUTESFILE", "/opt/hsm/default-sunpkcs11.cfg");
        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("SHAREDLIBRARY", "/opt/hsm/pkcs11.so");
        workerConfig.setProperty("SLOT", "3");
        workerConfig.setProperty("ATTRIBUTESFILE", "/opt/hsm/sunpkcs11.cfg");
        
        instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        actualToken = (MockedCryptoToken) instance.getCryptoToken();
        actualProperties = actualToken.getProps();
        
        expectedProperties = new Properties();
        expectedProperties.putAll(workerConfig.getProperties());
        expectedProperties.setProperty("SHAREDLIBRARY", "/opt/hsm/pkcs11.so");
        assertEquals("worker overriding SHAREDLIBRARY etc used", 
                expectedProperties.toString(), actualProperties.toString());
    }
    
    /** CryptoToken only holding its properties and offering a way to access them. */
    private static class MockedCryptoToken extends NullCryptoToken {

        private Properties props;
        
        public MockedCryptoToken() {
            super(CryptoTokenStatus.STATUS_ACTIVE);
        }

        @Override
        public void init(int workerId, Properties props) throws CryptoTokenInitializationFailureException {
            this.props = props;
        }

        public Properties getProps() {
            return props;
        }
    }
    
    /** Test instance with mocked GlobalConfigurationSession containing the supplied properties. */
    private static class TestSigner extends BaseSigner {

        /** Simulates global configuration. **/
        private final Properties globalProperties;

        public TestSigner(Properties globalProperties) {
            this.globalProperties = globalProperties;
        }
        
        @Override
        protected IGlobalConfigurationSession getGlobalConfigurationSession() {
            return new IGlobalConfigurationSession() {

                @Override
                public void setProperty(String scope, String key, String value) {
                    throw new UnsupportedOperationException("Not supported yet.");
                }

                @Override
                public boolean removeProperty(String scope, String key) {
                    throw new UnsupportedOperationException("Not supported yet.");
                }

                @Override
                public GlobalConfiguration getGlobalConfiguration() {
                    return new GlobalConfiguration(globalProperties, GlobalConfiguration.STATE_INSYNC, "1.2.3");
                }

                @Override
                public void resync() throws ResyncException {
                    throw new UnsupportedOperationException("Not supported yet.");
                }

                @Override
                public void reload() {
                    throw new UnsupportedOperationException("Not supported yet.");
                }
            };
        }

        @Override
        public ProcessResponse processData(ProcessRequest signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
            throw new UnsupportedOperationException("Not supported yet.");
        }
        
    }
}
