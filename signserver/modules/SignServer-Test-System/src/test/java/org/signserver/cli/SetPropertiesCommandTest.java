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
package org.signserver.cli;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.MatchIssuerWithType;
import org.signserver.common.MatchSubjectWithType;
import org.signserver.common.ReadOnlyWorkerException;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * System tests for the SetPropertiesCommand.
 *
 */
public class SetPropertiesCommandTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SetPropertiesCommandTest.class);

    private static final ModulesTestCase test = new ModulesTestCase();
    private final CLITestHelper cli = test.getAdminCLI();

    private static File propertiesFile;

    private static final int[] WORKER_ID = {90100, 90101, 90102};

    private final String SUBJECT_TYPE_ONE = "CERTIFICATE_SERIALNO";
    private final String SUBJECT_VALUE_ONE = "723507815f93333";
    private final String ISSUER_TYPE_ONE = "ISSUER_DN_BCSTYLE";
    private final String ISSUER_VALUE_ONE = "CN\\=DSS Root CA 10,OU\\=Testing,O\\=SignServer,C\\=SE";

    private final String SUBJECT_TYPE_TWO = "CERTIFICATE_SERIALNO";
    private final String SUBJECT_VALUE_TWO = "2c48d4863c3aaf83";
    private final String ISSUER_TYPE_TWO = "ISSUER_DN_BCSTYLE";
    private final String ISSUER_VALUE_TWO = "CN\\=DSS Sub CA 11,OU\\=Testing,O\\=SignServer,C\\=SE";

    @Before
    public void setUp() throws Exception {
        try {
            // Setup multiple workers with client cert authorization
            Properties props = new Properties();
            props.put("WORKER" + WORKER_ID[0] + ".AUTHCLIENT1.ISSUER.VALUE", ISSUER_VALUE_ONE);
            props.put("WORKER" + WORKER_ID[0] + ".NAME", "PlainSigner1" + System.currentTimeMillis());
            props.put("WORKER" + WORKER_ID[0] + ".AUTHCLIENT1.SUBJECT.TYPE", SUBJECT_TYPE_ONE);
            props.put("WORKER" + WORKER_ID[0] + ".AUTHCLIENT1.SUBJECT.VALUE", SUBJECT_VALUE_ONE);
            props.put("WORKER" + WORKER_ID[0] + ".AUTHCLIENT1.ISSUER.TYPE", ISSUER_TYPE_ONE);

            props.put("WORKER" + WORKER_ID[1] + ".AUTHCLIENT1.ISSUER.VALUE", ISSUER_VALUE_TWO);
            props.put("WORKER" + WORKER_ID[1] + ".NAME", "PlainSigner2" + System.currentTimeMillis());
            props.put("WORKER" + WORKER_ID[1] + ".AUTHCLIENT1.SUBJECT.TYPE", SUBJECT_TYPE_TWO);
            props.put("WORKER" + WORKER_ID[1] + ".AUTHCLIENT1.SUBJECT.VALUE", SUBJECT_VALUE_TWO);
            props.put("WORKER" + WORKER_ID[1] + ".AUTHCLIENT1.ISSUER.TYPE", ISSUER_TYPE_TWO);

            props.put("WORKER" + WORKER_ID[2] + ".AUTHCLIENT1.ISSUER.VALUE", ISSUER_VALUE_ONE);
            props.put("WORKER" + WORKER_ID[2] + ".NAME", "PlainSigner3" + System.currentTimeMillis());
            props.put("WORKER" + WORKER_ID[2] + ".AUTHCLIENT1.SUBJECT.TYPE", SUBJECT_TYPE_ONE);
            props.put("WORKER" + WORKER_ID[2] + ".AUTHCLIENT1.SUBJECT.VALUE", SUBJECT_VALUE_ONE);
            props.put("WORKER" + WORKER_ID[2] + ".AUTHCLIENT1.ISSUER.TYPE", ISSUER_TYPE_ONE);

            // Create properties file from declared properties above
            propertiesFile = File.createTempFile("test-" + System.currentTimeMillis() + ".properties", null);
            try (FileOutputStream os = new FileOutputStream(propertiesFile)) {
                props.store(os, null);
            }
        } catch (IOException e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }

    }

    @After
    public void tearDown() throws ReadOnlyWorkerException, IllegalRequestException {
        FileUtils.deleteQuietly(propertiesFile);
        for (int id : WORKER_ID) {
            test.removeWorker(id);
        }
    }

    @Test
    public void importMultipleWorkersWithAuthorization() throws IOException, UnexpectedCommandFailureException {
        LOG.info("importMultipleWorkersWithAuthorization");

        // Execute the setproperties command with the supplied properties file
        cli.execute("setproperties", propertiesFile.getAbsolutePath());

        // Retrieve CertificateMatchingRule object from Collection.
        CertificateMatchingRule certRuleSignerOne = test.getWorkerSession().getAuthorizedClientsGen2(WORKER_ID[0]).iterator().next();
        CertificateMatchingRule certRuleSignerTwo = test.getWorkerSession().getAuthorizedClientsGen2(WORKER_ID[1]).iterator().next();
        CertificateMatchingRule certRuleSignerThree = test.getWorkerSession().getAuthorizedClientsGen2(WORKER_ID[2]).iterator().next();

        // Test PlainSigner1
        assertEquals(MatchIssuerWithType.ISSUER_DN_BCSTYLE, certRuleSignerOne.getMatchIssuerWithType());
        assertEquals(ISSUER_VALUE_ONE, certRuleSignerOne.getMatchIssuerWithValue());
        assertEquals(MatchSubjectWithType.CERTIFICATE_SERIALNO, certRuleSignerOne.getMatchSubjectWithType());
        assertEquals(SUBJECT_VALUE_ONE, certRuleSignerOne.getMatchSubjectWithValue());

        // Test PlainSigner2
        assertEquals(MatchIssuerWithType.ISSUER_DN_BCSTYLE, certRuleSignerTwo.getMatchIssuerWithType());
        assertEquals(ISSUER_VALUE_TWO, certRuleSignerTwo.getMatchIssuerWithValue());
        assertEquals(MatchSubjectWithType.CERTIFICATE_SERIALNO, certRuleSignerTwo.getMatchSubjectWithType());
        assertEquals(SUBJECT_VALUE_TWO, certRuleSignerTwo.getMatchSubjectWithValue());

        // Test PlainSigner3
        assertEquals(MatchIssuerWithType.ISSUER_DN_BCSTYLE, certRuleSignerThree.getMatchIssuerWithType());
        assertEquals(ISSUER_VALUE_ONE, certRuleSignerThree.getMatchIssuerWithValue());
        assertEquals(MatchSubjectWithType.CERTIFICATE_SERIALNO, certRuleSignerThree.getMatchSubjectWithType());
        assertEquals(SUBJECT_VALUE_ONE, certRuleSignerThree.getMatchSubjectWithValue());
    }
}
