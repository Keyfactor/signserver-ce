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
package org.signserver.admin.cli.defaultimpl;

import org.apache.log4j.Logger;
import org.junit.Test;
import static org.junit.Assert.*;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.common.MatchSubjectWithType;

/**
 * Unit tests for the ClientsAuthorizationCommand.
 *
 * Focus is on checking of command arguments etc.
 * An other system test will check that add/remove/list actually works.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ClientsAuthorizationCommandUnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ClientsAuthorizationCommandUnitTest.class);

    /**
     * Tests that an unknown argument gives an argument exception.
     * @throws Exception
     */
    @Test(expected = IllegalCommandArgumentsException.class)
    public void testUnknownArgument() throws Exception {
        LOG.info("testUnknownArgument");
        ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
        instance.execute("-notExistingCommand"); // Argument that does not exist
    }

    /**
     * Tests that -list without other arguments gives an argument exception.
     * @throws Exception
     */
    @Test(expected = IllegalCommandArgumentsException.class)
    public void testListMissingArgumentWorker() throws Exception {
        LOG.info("testListMissingArgumentWorker");
        ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
        instance.execute("-list"); // Missing -worker argument
    }

    /**
     * Tests that -worker without other arguments gives an argument exception.
     * @throws Exception
     */
    @Test(expected = IllegalCommandArgumentsException.class)
    public void testWorkerMissingOperationArgument() throws Exception {
        LOG.info("testWorkerMissingOperationArgument");
        ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
        instance.execute("-worker",  "SampleSigner"); // Missing -list, -add or -remove
    }

    /**
     * Tests that -add without -matchSubjectWithType argument gives an argument exception.
     * @throws Exception
     */
    @Test(expected = IllegalCommandArgumentsException.class)
    public void testAddMissingArgumentMatchSubjectWithType() throws Exception {
        LOG.info("testAddMissingArgumentMatchSubjectWithType");
        ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
        instance.execute("-worker", "SampleSigner", "-add", "-matchSubjectWithValue", "Client One", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule"); // Missing "-matchSubjectWithType", "SUBJECT_RDN_CN"
    }

    /**
     * Tests that -add without -matchSubjectWithValue argument gives an argument exception.
     * @throws Exception
     */
    @Test(expected = IllegalCommandArgumentsException.class)
    public void testAddMissingArgumentMatchSubjectWithValue() throws Exception {
        LOG.info("testAddMissingArgumentMatchSubjectWithValue");
        ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
        instance.execute("-worker", "SampleSigner", "-add", "-matchSubjectWithType", "SUBJECT_RDN_CN", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule"); // Missing "-matchSubjectWithValue", "Client One",
    }

    /**
     * Tests that -add without -matchIssuerWithValue argument gives an argument exception.
     * @throws Exception
     */
    @Test(expected = IllegalCommandArgumentsException.class)
    public void testAddMissingArgumentMatchIssuerWithValue() throws Exception {
        LOG.info("testAddMissingArgumentMatchIssuerWithValue");
        ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
        instance.execute("-worker", "SampleSigner", "-add", "-matchSubjectWithType", "SUBJECT_RDN_CN", "-matchSubjectWithValue", "Client One", "-description", "my rule"); // Missing "-matchIssuerWithValue", "CN=AdminCA1, C=SE",
    }

    /**
     * Tests that -remove without -matchSubjectWithType argument gives an argument exception.
     * @throws Exception
     */
    @Test(expected = IllegalCommandArgumentsException.class)
    public void testRemoveMissingArgumentMatchSubjectWithType() throws Exception {
        LOG.info("testRemoveMissingArgumentMatchSubjectWithType");
        ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
        instance.execute("-worker", "SampleSigner", "-remove", "-matchSubjectWithValue", "Client One", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule"); // Missing "-matchSubjectWithType", "SUBJECT_RDN_CN"
    }

    /**
     * Tests that -remove without -matchSubjectWithValue argument gives an argument exception.
     * @throws Exception
     */
    @Test(expected = IllegalCommandArgumentsException.class)
    public void testRemoveMissingArgumentMatchSubjectWithValue() throws Exception {
        LOG.info("testRemoveMissingArgumentMatchSubjectWithValue");
        ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
        instance.execute("-worker", "SampleSigner", "-remove", "-matchSubjectWithType", "SUBJECT_RDN_CN", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule"); // Missing "-matchSubjectWithValue", "Client One",
    }

    /**
     * Tests that -remove without -matchIssuerWithValue argument gives an argument exception.
     * @throws Exception
     */
    @Test(expected = IllegalCommandArgumentsException.class)
    public void testRemoveMissingArgumentMatchIssuerWithValue() throws Exception {
        LOG.info("testRemoveMissingArgumentMatchIssuerWithValue");
        ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
        instance.execute("-worker", "SampleSigner", "-remove", "-matchSubjectWithType", "SUBJECT_RDN_CN", "-matchSubjectWithValue", "Client One", "-description", "my rule"); // Missing "-matchIssuerWithValue", "CN=AdminCA1, C=SE",
    }

    /**
     * Tests that -add and -remove can not be specified at the same time.
     * @throws Exception
     */
    @Test(expected = IllegalCommandArgumentsException.class)
    public void testAddAndRemove() throws Exception {
        LOG.info("testAddAndRemove");
        ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
        instance.execute("-worker", "SampleSigner", "-remove", "-add", "-matchSubjectWithType", "SUBJECT_RDN_CN", "-matchSubjectWithValue", "Client One", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule"); // Both -remove and -add
    }

    /**
     * Tests that -add and -list can not be specified at the same time.
     * @throws Exception
     */
    @Test(expected = IllegalCommandArgumentsException.class)
    public void testAddAndList() throws Exception {
        LOG.info("testAddAndList");
        ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
        instance.execute("-worker", "SampleSigner", "-list", "-add", "-matchSubjectWithType", "SUBJECT_RDN_CN", "-matchSubjectWithValue", "Client One", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule"); // Both -remove and -add
    }

    /**
     * Tests that -add and -list can not be specified at the same time.
     * @throws Exception
     */
    @Test(expected = IllegalCommandArgumentsException.class)
    public void testRemoveAndList() throws Exception {
        LOG.info("testRemoveAndList");
        ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
        instance.execute("-worker", "SampleSigner", "-list", "-remove", "-matchSubjectWithType", "SUBJECT_RDN_CN", "-matchSubjectWithValue", "Client One", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule"); // Both -remove and -add
    }

    /**
     * Tests that one of -add, -list and -remove must be specified.
     * @throws Exception
     */
    @Test(expected = IllegalCommandArgumentsException.class)
    public void testNoOperation() throws Exception {
        LOG.info("testNoOperation");
        ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
        instance.execute("-worker", "SampleSigner", "-matchSubjectWithType", "SUBJECT_RDN_CN", "-matchSubjectWithValue", "Client One", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule"); // No -list, -add or -remove
    }

    /**
     * Tests that there is an error if an incorrect matchSubjectWithType is specified.
     * @throws java.lang.Exception
     */
    @Test
    public void testAddUnknownMatchSubjectWithType() throws Exception {
        try {
            LOG.info("testAddUnknownMatchSubjectWithType");
            ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
            instance.execute("-worker", "SampleSigner", "-add", "-matchSubjectWithType", "_incorrectType_", "-matchSubjectWithValue", "Client One", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule");
            fail("Expected IllegalCommandArgumentsException due to incorrect type");
        } catch (IllegalCommandArgumentsException expected) {
            assertEquals("Unknown matchSubjectWithType value provided. Possible values are: [CERTIFICATE_SERIALNO, SUBJECT_RDN_CN, SUBJECT_RDN_SERIALNO, SUBJECT_RDN_C, SUBJECT_RDN_DC, SUBJECT_RDN_ST, SUBJECT_RDN_L, SUBJECT_RDN_O, SUBJECT_RDN_OU, SUBJECT_RDN_TITLE, SUBJECT_RDN_UID, SUBJECT_RDN_E, SUBJECT_ALTNAME_RFC822NAME, SUBJECT_ALTNAME_MSUPN]", expected.getMessage());
        }
    }
    
    /**
     * Tests that there is an error if an incorrect matchIssuerWithType is specified.
     * @throws java.lang.Exception
     */
    @Test
    public void testAddUnknownMatchIssuerWithType() throws Exception {
        try {
            LOG.info("testAddUnknownMatchIssuerWithType");
            ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
            instance.execute("-worker", "SampleSigner", "-add", "-matchSubjectWithType", MatchSubjectWithType.SUBJECT_RDN_CN.name(), "-matchSubjectWithValue", "Client One", "-matchIssuerWithType", "_incorrectIssuerType_", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule");
            fail("Expected IllegalCommandArgumentsException due to incorrect type");
        } catch (IllegalCommandArgumentsException expected) {
            assertEquals("Unknown matchIssuerWithType value provided. Possible values are: [ISSUER_DN_BCSTYLE]", expected.getMessage());
        }
    }
    
    /**
     * Tests that setting both -matchSubjectWithValue and -cert at the same time
     * is not allowed.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testBothMatchSubjectWithValueAndCertNotAllowed() throws Exception {
        try {
            LOG.info("testAddUnknownMatchIssuerWithType");
            ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
            instance.execute("-worker", "SampleSigner", "-add", "-matchSubjectWithType", MatchSubjectWithType.SUBJECT_RDN_CN.name(),
                             "-matchSubjectWithValue", "Client One", "-cert", "/tmp/cert.pem", "-description", "my rule");
            fail("Expected IllegalCommandArgumentsException due to conflicting parameters");
        } catch (IllegalCommandArgumentsException expected) {
            assertEquals("Can not specify -cert at the same time as -matchSubjectWithValue and/or -matchIssuerWithValue",
                         expected.getMessage());
        }
    }

    /**
     * Tests that setting both -matchIssuerWithValue and -cert at the same time
     * is not allowed.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testBothMatchIssuerWithValueAndCertNotAllowed() throws Exception {
        try {
            LOG.info("testAddUnknownMatchIssuerWithType");
            ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
            instance.execute("-worker", "SampleSigner", "-add", "-matchSubjectWithType", MatchSubjectWithType.SUBJECT_RDN_CN.name(),
                             "-matchIssuerWithValue", "CN=Issuing CA, O=SignServer, C=SE", "-cert", "/tmp/cert.pem", "-description", "my rule");
            fail("Expected IllegalCommandArgumentsException due to conflicting parameters");
        } catch (IllegalCommandArgumentsException expected) {
            assertEquals("Can not specify -cert at the same time as -matchSubjectWithValue and/or -matchIssuerWithValue",
                         expected.getMessage());
        }
    }
    
    /**
     * Tests that setting both -matchSubjectWithValue, -matchIssuerWithValue and -cert at the same time
     * is not allowed.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testBothMatchSubjectWithValueAndIssuerWithValueAndCertNotAllowed() throws Exception {
        try {
            LOG.info("testAddUnknownMatchIssuerWithType");
            ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
            instance.execute("-worker", "SampleSigner", "-add", "-matchSubjectWithType", MatchSubjectWithType.SUBJECT_RDN_CN.name(),
                             "-matchIssuerWithValue", "CN=Issuing CA, O=SignServer, C=SE", "-cert", "/tmp/cert.pem", "-description", "my rule");
            fail("Expected IllegalCommandArgumentsException due to conflicting parameters");
        } catch (IllegalCommandArgumentsException expected) {
            assertEquals("Can not specify -cert at the same time as -matchSubjectWithValue and/or -matchIssuerWithValue",
                         expected.getMessage());
        }
    }
    
    /**
     * Tests that -add with incorrect issuer DN gives an error.
     * @throws Exception
     */
    @Test(expected = IllegalCommandArgumentsException.class)
    public void testAddIncorrectIssuerDN() throws Exception {
        LOG.info("testRemoveMissingArgumentMatchSubjectWithValue");
        ClientsAuthorizationCommand instance = new ClientsAuthorizationCommand();
        instance.execute("-worker", "SampleSigner", "-add", "-matchSubjectWithType", "SUBJECT_RDN_CN", "-matchSubjectWithValue", "Client One", "-matchIssuerWithValue", "CN=AdminCA1, C=SE,", "-description", "my rule"); // Incorrect issuer DN (ends with ',')
    }
}
