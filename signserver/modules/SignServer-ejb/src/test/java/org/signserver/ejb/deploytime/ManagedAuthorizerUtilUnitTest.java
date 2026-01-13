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
package org.signserver.ejb.deploytime;

import org.apache.log4j.Logger;
import org.junit.Test;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.MatchIssuerWithType;
import org.signserver.common.MatchSubjectWithType;
import org.signserver.common.WorkerConfig;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.signserver.ejb.deploytime.ManagedAuthorizerUtil.validateInput;
import static org.signserver.ejb.deploytime.ManagedAuthorizerUtil.parse;
import static org.signserver.ejb.deploytime.ManagedAuthorizerUtil.sanitizeDescription;

import java.util.Collection;
import java.util.Properties;

/**
 * Unit tests for ManagedAuthorizerUtil.
 */
public class ManagedAuthorizerUtilUnitTest {
    private static final Logger LOG = Logger.getLogger(ManagedAuthorizerUtilUnitTest.class);

    final String ISSUER_TYPE_PROPERTY    = "managed.admincert.issuer.type.";
    final String ISSUER_VALUE_PROPERTY   = "managed.admincert.issuer.value.";
    final String SUBJECT_TYPE_PROPERTY   = "managed.admincert.subject.type.";
    final String SUBJECT_VALUE_PROPERTY  = "managed.admincert.subject.value.";
    final String DESCRIPTION_PROPERTY    = "managed.admincert.description.";

    final String ISSUER_TYPE             = "ISSUER_DN_BCSTYLE";
    final String ISSUER_VALUE            = "CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE";
    final String SUBJECT_TYPE            = "CERTIFICATE_SERIALNO";
    final String SUBJECT_VALUE           = "26fabff8dca558a515a792701fb3f3628b6c94b7";
    final String DESCRIPTION             = "Sample";
    final String NONEXSTING              = "NONEXSTING";

    private final boolean valid = true;
    private final boolean invalid = false;
    private final boolean nonexisting = true;

    /**
     * Testing if having an invalid (nonexisting) subject or issuer type should throw IllegalArgumentException.
     */
    @Test
    public void testParseWithInvalidIssuerOrSubjectType() {
        LOG.info("testParseWithInvalidIssuerType");
        assertThrows("Should throw IllegalArgumentException",
                IllegalArgumentException.class, () -> parse(whereIssuerTypeIs(invalid, 1)));
        assertThrows("Should throw IllegalArgumentException",
                IllegalArgumentException.class, () -> parse(whereSubjectTypeIs(invalid, 1)));
    }

    /**
     * Testing if managed.admincert.description.x is not specified, then it should still be present
     * as an empty string.
     */
    @Test
    public void testParseWithMissingDescription() {
        LOG.info("testParseWithInvalidDescription");
        final WorkerConfig config = parse(whereDescriptionIs(nonexisting, 1));
        final Collection<CertificateMatchingRule> clients = config.getAuthorizedClientsGen2();
        final CertificateMatchingRule certMatch = clients.iterator().next();

        assertNotNull("Certificate matching rules should not be null", certMatch);
        assertEquals("Description should be sanitized", "", certMatch.getDescription());
    }

    /**
     * Testing having multiple valid certificate rules on different indices.
     */
    @Test
    public void testParseWithValidIssuerOrSubjectType() {
        LOG.info("testParseWithValidIssuerOrSubjectType");
        Properties properties = new Properties();
        properties.putAll(whereIssuerTypeIs(valid, 1));
        properties.putAll(whereIssuerTypeIs(valid, 3));
        properties.putAll(whereIssuerTypeIs(valid, 8));

        final WorkerConfig config = parse(properties);
        final Collection<CertificateMatchingRule> clients = config.getAuthorizedClientsGen2();

        for (final CertificateMatchingRule certMatch : clients) {
            assertNotNull("Certificate matching rules should not be null", certMatch);
            assertEquals("Issuer type", MatchIssuerWithType.valueOf(ISSUER_TYPE), certMatch.getMatchIssuerWithType());
            assertEquals("Issuer value", ISSUER_VALUE, certMatch.getMatchIssuerWithValue());
            assertEquals("Subject type", MatchSubjectWithType.valueOf(SUBJECT_TYPE), certMatch.getMatchSubjectWithType());
            assertEquals("Subject value", SUBJECT_VALUE, certMatch.getMatchSubjectWithValue());
        }
    }

    /**
     * Testing that input validator works as expected.
     */
    @Test
    public void testValidatingInput() {
        LOG.info("testValidatingInput");
        assertTrue("Should be true: ", validateInput(ISSUER_VALUE));
        assertFalse("Should be false: ", validateInput(""));
        assertFalse("Should be false: ", validateInput(null));
        assertFalse("Should be false: ", validateInput("${Test}"));
    }

    /**
     * Testing that the description sanitizer works with given input.
     */
    @Test
    public void testSanitizeDescription() {
        LOG.info("testSanitizeDescription");
        assertEquals("Should return empty string", "", sanitizeDescription("${Test}"));
        assertEquals("Should return empty string", "", sanitizeDescription(null));
        assertEquals("Should return parameter", "Test", sanitizeDescription("Test"));
    }

    /**
     * Helper method to create certificate rule properties.
     * @param valid if the MatchIssuerWithType should be valid or not.
     * @param index what property index it should belong to.
     * @return properties object containing the certificate matching rules
     */
    private Properties whereIssuerTypeIs(boolean valid, int index) {
        Properties properties = new Properties();
        properties.put(ISSUER_TYPE_PROPERTY + index, valid ? ISSUER_TYPE : NONEXSTING);
        properties.put(ISSUER_VALUE_PROPERTY + index, ISSUER_VALUE);
        properties.put(SUBJECT_TYPE_PROPERTY + index, SUBJECT_TYPE);
        properties.put(SUBJECT_VALUE_PROPERTY + index, SUBJECT_VALUE);
        properties.put(DESCRIPTION_PROPERTY + index, DESCRIPTION);

        return properties;
    }

    /**
     * Helper method to create certificate rule properties.
     * @param valid if the MatchSubjectWithType should be valid or not.
     * @param index what property index it should belong to
     * @return properties object containing the certificate matching rules
     */
    private Properties whereSubjectTypeIs(boolean valid, int index) {
        Properties properties = new Properties();
        properties.put(ISSUER_TYPE_PROPERTY + index, ISSUER_TYPE);
        properties.put(ISSUER_VALUE_PROPERTY + index, ISSUER_VALUE);
        properties.put(SUBJECT_TYPE_PROPERTY + index, valid ? SUBJECT_TYPE : NONEXSTING);
        properties.put(SUBJECT_VALUE_PROPERTY + index, SUBJECT_VALUE);
        properties.put(DESCRIPTION_PROPERTY + index, DESCRIPTION);

        return properties;
    }

    /**
     * Helper method to create certificate rule properties.
     * @param nonexsiting if the description should be present or not.
     * @param index what property index the properties should belong to.
     * @return properties object containing the certificate matching rules.
     */
    private Properties whereDescriptionIs(boolean nonexsiting, int index) {
        Properties properties = new Properties();
        properties.put(ISSUER_TYPE_PROPERTY + index, ISSUER_TYPE);
        properties.put(ISSUER_VALUE_PROPERTY + index, ISSUER_VALUE);
        properties.put(SUBJECT_TYPE_PROPERTY + index, SUBJECT_TYPE);
        properties.put(SUBJECT_VALUE_PROPERTY + index, SUBJECT_VALUE);
        if (!nonexsiting) {
            properties.put(DESCRIPTION_PROPERTY + index, DESCRIPTION);
        }

        return properties;
    }
}
