/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.onetime.caconnector;

import java.util.List;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import static org.signserver.module.onetime.caconnector.EjbcaWSCAConnector.PROPERTY_CERTIFICATEPROFILE;
import static org.signserver.module.onetime.caconnector.EjbcaWSCAConnector.PROPERTY_ENDENTITYPROFILE;
import org.signserver.module.renewal.ejbcaws.gen.UserDataVOWS;
import org.signserver.server.IAuthorizer;
import org.signserver.server.SignServerContext;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for EjbcaWSCAConnector.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class EjbcaWSCAConnectorUnitTest {

    /**
     * Test that missing required properties gives the correct errors.
     *
     * @throws Exception
     */
    @Test
    public void test01CheckRequiredProperties() throws Exception {
        WorkerConfig workerConfig = new WorkerConfig();

        final EjbcaWSCAConnector instance = new EjbcaWSCAConnector();
        instance.init(workerConfig, new SignServerContext());

        final List<String> errors = instance.getFatalErrors(null, null);

        assertTrue("Contains error about missing TLSCLIENTKEY",
                errors.contains("Missing TLSCLIENTKEY property"));

        assertTrue("Contains error about missing TRUSTSTORETYPE",
                errors.contains("Missing TRUSTSTORETYPE property"));

        assertTrue("Contains error about missing TRUSTSTOREPATH or TRUSTSTOREVALUE",
                errors.contains("Missing TRUSTSTOREPATH or TRUSTSTOREVALUE property"));

        assertTrue("Contains error about missing SIGNATUREALGORITHM",
                errors.contains("Missing CERTSIGNATUREALGORITHM property"));

        assertTrue("Contains error about missing EJBCAWSURL property",
                errors.contains("Missing EJBCAWSURL property"));

        assertTrue("Contains error about missing ENDENTITYPROFILE property",
                errors.contains("Missing " + PROPERTY_ENDENTITYPROFILE + " property"));

        assertTrue("Contains error about missing CERTIFICATEPROFILE property",
                errors.contains("Missing " + PROPERTY_CERTIFICATEPROFILE + " property"));

        assertTrue("Contains error about missing USERNAME_PATTERN property",
                errors.contains("Missing USERNAME_PATTERN property"));

        assertTrue("Contains error about missing SUBJECTDN_PATTERN property",
                errors.contains("Missing SUBJECTDN_PATTERN property"));

        assertTrue("Contains error about missing USERNAME_PATTERN property",
                errors.contains("Missing USERNAME_PATTERN property"));

        assertTrue("Contains error about missing CANME property",
                errors.contains("Missing CANME property"));
    }

    /**
     * Test that providing both TRUSTSTOREPATH & TRUSTSTOREVALUE gives error.
     *
     * @throws Exception
     */
    @Test
    public void test02_TRUSTSTOREPATH_TRUSTSTORE_Both_Not_Allowed() throws Exception {
        WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty("TRUSTSTOREPATH", "dummy_path");
        workerConfig.setProperty("TRUSTSTOREVALUE", "dummy_value");

        final EjbcaWSCAConnector instance = new EjbcaWSCAConnector();
        instance.init(workerConfig, new SignServerContext());

        final List<String> errors = instance.getFatalErrors(null, null);

        assertTrue("Contains error about missing TLSCLIENTKEY",
                errors.contains("Can not specify both TRUSTSTOREPATH and TRUSTSTOREVALUE property"));
    }

    /**
     * Test that providing invalid TRUSTSTORETYPE gives error.
     *
     * @throws Exception
     */
    @Test
    public void test03_Invalid_TRUSTSTORETYPE() throws Exception {
        WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty("TRUSTSTORETYPE", "invalid_value");

        final EjbcaWSCAConnector instance = new EjbcaWSCAConnector();
        instance.init(workerConfig, new SignServerContext());

        final List<String> errors = instance.getFatalErrors(null, null);

        assertTrue("Contains error about invalid TRUSTSTORETYPE property",
                errors.contains("Invalid TRUSTSTORETYPE property"));

    }

    /**
     * Test that TRUSTSTOREPASSWORD is required when TRUSTSTORETYPE is JKS.
     *
     * @throws Exception
     */
    @Test
    public void test04_Required_TRUSTSTOREPASSWORD_TRUSTSTORETYPE_JKS() throws Exception {
        WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty("TRUSTSTORETYPE", "JKS");

        final EjbcaWSCAConnector instance = new EjbcaWSCAConnector();
        instance.init(workerConfig, new SignServerContext());

        final List<String> errors = instance.getFatalErrors(null, null);

        assertTrue("Contains error about invalid TRUSTSTORETYPE property",
                errors.contains("Missing TRUSTSTOREPASSWORD property"));
    }

    /**
     * Test that Empty TRUSTSTOREPASSWORD is allowed when TRUSTSTORETYPE is JKS.
     *
     * @throws Exception
     */
    @Test
    public void test05_Empty_TRUSTSTOREPASSWORD_Allowed_TRUSTSTORETYPE_JKS() throws Exception {
        WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty("TRUSTSTORETYPE", "JKS");
        workerConfig.setProperty("TRUSTSTOREPASSWORD", "");

        final EjbcaWSCAConnector instance = new EjbcaWSCAConnector();
        instance.init(workerConfig, new SignServerContext());

        final List<String> errors = instance.getFatalErrors(null, null);

        assertFalse("Contains error about invalid TRUSTSTORETYPE property",
                errors.contains("Missing TRUSTSTOREPASSWORD property"));
    }

    /**
     * Test that TRUSTSTOREPASSWORD is not required when TRUSTSTORETYPE is PEM.
     *
     * @throws Exception
     */
    @Test
    public void test06_Not_Required_TRUSTSTOREPASSWORD_TRUSTSTORETYPE_PEM() throws Exception {
        WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty("TRUSTSTORETYPE", "PEM");

        final EjbcaWSCAConnector instance = new EjbcaWSCAConnector();
        instance.init(workerConfig, new SignServerContext());

        final List<String> errors = instance.getFatalErrors(null, null);

        assertFalse("Contains error about invalid TRUSTSTORETYPE property",
                errors.contains("Missing TRUSTSTOREPASSWORD property"));
    }
    
    /**
     * Test that values of SUBJECTDN_PATTERN, USERNAME_PATTERN and
     * SUBJECTALTNAME_PATTERN fields are included in UserData as per specified
     * pattern.
     *
     * @throws Exception
     */
    @Test
    public void test07_testParamsWithPattern_Set1() throws Exception {
        WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty("SUBJECTDN_PATTERN", "CN=User ${username},UID=${transactionId},O=SignServer Testing,C=SE");
        workerConfig.setProperty("USERNAME_PATTERN", "onetime-${transactionId}");
        workerConfig.setProperty("SUBJECTALTNAME_PATTERN", "dNSName=signservertest");

        final EjbcaWSCAConnector instance = new EjbcaWSCAConnector();
        instance.init(workerConfig, new SignServerContext());

        // Set dummy transationId
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "123456");

        // Set dummy userName
        final LogMap logMap = LogMap.getInstance(requestContext);
        logMap.put(IAuthorizer.LOG_USERNAME, new Loggable() {
            @Override
            public String toString() {
                return "testUser1";
            }
        });

        UserDataVOWS userData = instance.createUserData("oneTimeDummyKey", requestContext);
        assertEquals("SUBJECTDN_PATTERN should match with expected pattern",
                "CN=User testUser1,UID=123456,O=SignServer Testing,C=SE", userData.getSubjectDN());
        assertEquals("USERNAME_PATTERN should match with expected pattern",
                "onetime-123456", userData.getUsername());
        assertEquals("SUBJECTALTNAME_PATTERN should match with expected pattern",
                "dNSName=signservertest", userData.getSubjectAltName());
    }
    
    /**
     * Test that values of SUBJECTDN_PATTERN, USERNAME_PATTERN and
     * SUBJECTALTNAME_PATTERN fields are included in UserData as per specified
     * pattern.
     *
     * @throws Exception
     */
    @Test
    public void test07_testParamsWithPattern_Set2() throws Exception {
        WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty("SUBJECTDN_PATTERN", "UID=${transactionId},CN=User ${username},O=SignServer ShortLived Testing,C=IN");
        workerConfig.setProperty("USERNAME_PATTERN", "short-lived-onetime-${transactionId}");
        workerConfig.setProperty("SUBJECTALTNAME_PATTERN", "uri=https://example.com");

        final EjbcaWSCAConnector instance = new EjbcaWSCAConnector();
        instance.init(workerConfig, new SignServerContext());

        // Set dummy transationId
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "987654");

        // Set dummy userName
        final LogMap logMap = LogMap.getInstance(requestContext);
        logMap.put(IAuthorizer.LOG_USERNAME, new Loggable() {
            @Override
            public String toString() {
                return "testUser2";
            }
        });

        UserDataVOWS userData = instance.createUserData("shortLivedDummyKey", requestContext);
        assertEquals("SUBJECTDN_PATTERN should match with expected pattern",
                "UID=987654,CN=User testUser2,O=SignServer ShortLived Testing,C=IN", userData.getSubjectDN());
        assertEquals("USERNAME_PATTERN should match with expected pattern",
                "short-lived-onetime-987654", userData.getUsername());
        assertEquals("SUBJECTALTNAME_PATTERN should match with expected pattern",
                "uri=https://example.com", userData.getSubjectAltName());
    }

}
