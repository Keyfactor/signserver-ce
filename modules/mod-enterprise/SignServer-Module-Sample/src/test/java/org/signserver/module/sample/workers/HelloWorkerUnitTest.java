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
package org.signserver.module.sample.workers;

import java.nio.charset.StandardCharsets;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.SignatureRequest;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.testutils.ModulesTestCase;

/**
 * Unit tests for the HelloWorker class.
 *
 * This class only contains standalone unit tests.
 *
 * Tests requiring a running application server are o be put in a separate
 * module, ie SignServer-Test-System, SignServer-Test-Enterprise or a new custom
 * system test module for this module, SignServer-Test-Sample.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class HelloWorkerUnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(HelloWorkerUnitTest.class);

    public HelloWorkerUnitTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Tests that the GREETING property is required.
     * @throws Exception
     */
    @Test
    public void testInit_GreetingPropertyRequired() throws Exception {
        LOG.info("testInit_GreetingPropertyRequired");

        // Config without GREETING property
        WorkerConfig config = new WorkerConfig();

        HelloWorker instance = new HelloWorker();
        instance.init(123, config, null, null);
        final String errors = instance.getFatalErrors(null).toString();
        
        // Check that there is an error for the GREETING property
        assertTrue("errors: " + errors, errors.contains("GREETING"));
    }

    /**
     * Test of processData method, of class HelloWorker.
     * @throws Exception
     */
    @Test
    public void testProcessData_BothProperties() throws Exception {
        LOG.info("processData");
        
        // Config with both properties set
        WorkerConfig config = new WorkerConfig();
        config.setProperty("GREETING", "Hello on you");
        config.setProperty("SUFFIX", " :D");
        
        // Init
        HelloWorker instance = new HelloWorker();
        instance.init(123, config, null, null);
        
        // Send request
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "123456789");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData("Adam".getBytes(StandardCharsets.UTF_8));
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            SignatureRequest signRequest = new SignatureRequest(1, requestData, responseData);
            instance.processData(signRequest, requestContext);

            // Check result
            final String result = new String(responseData.toReadableData().getAsByteArray(), StandardCharsets.UTF_8);
            assertEquals("Hello on you Adam :D", result);
        }
    }

    /**
     * Tests that the default value for SUFFIX is used if not configured.
     * @throws Exception 
     */
    @Test
    public void testProcessData_WithoutSuffix() throws Exception {
        LOG.info("testProcessData_WithoutSuffix");
        
        // Config without SUFFIX set
        WorkerConfig config = new WorkerConfig();
        config.setProperty("GREETING", "Hi");
        
        // Init
        HelloWorker instance = new HelloWorker();
        instance.init(123, config, null, null);
        
        // Send request
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "123456789");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData("Bertil".getBytes(StandardCharsets.UTF_8));
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            SignatureRequest signRequest = new SignatureRequest(1, requestData, responseData);
            instance.processData(signRequest, requestContext);

            // Check result, should use the default suffix
            final String result = new String(responseData.toReadableData().getAsByteArray(), StandardCharsets.UTF_8);
            assertEquals("Hi Bertil!", result);
        }
    }

    /**
     * Tests that there is a SignServerException when the configuration is not
     * correct.
     * @throws Exception 
     */
    @Test(expected = SignServerException.class)
    public void testProcessData_Misconfigured() throws Exception {
        LOG.info("testProcessData_Misconfigured");
        
        // Config without the required GREETING property
        WorkerConfig config = new WorkerConfig();
        
        // Init
        HelloWorker instance = new HelloWorker();
        instance.init(123, config, null, null);
        
        // Send request
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData("Bertil".getBytes(StandardCharsets.UTF_8));
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            SignatureRequest signRequest = new SignatureRequest(1, requestData, responseData);
            RequestContext requestContext = new RequestContext();
            requestContext.put(RequestContext.TRANSACTION_ID, "123456789");
            instance.processData(signRequest, requestContext);
        }
    }

    /**
     * Tests that there is a IllegalRequestException when the input data is
     * not correct (empty).
     * @throws Exception 
     */
    @Test(expected = IllegalRequestException.class)
    public void testProcessData_NoData() throws Exception {
        LOG.info("testProcessData_NoData");
        
        // Ok config
        WorkerConfig config = new WorkerConfig();
        config.setProperty("GREETING", "Hello on you");
        config.setProperty("SUFFIX", " :D");
        
        // Init
        HelloWorker instance = new HelloWorker();
        instance.init(123, config, null, null);
        
        // Send request with empty data
        final byte[] emptyData = new byte[0];
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(emptyData);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureRequest signRequest = new SignatureRequest(1, requestData, responseData);
            RequestContext requestContext = new RequestContext();
            requestContext.put(RequestContext.TRANSACTION_ID, "123456789");
            instance.processData(signRequest, requestContext);
        }
    }

}
