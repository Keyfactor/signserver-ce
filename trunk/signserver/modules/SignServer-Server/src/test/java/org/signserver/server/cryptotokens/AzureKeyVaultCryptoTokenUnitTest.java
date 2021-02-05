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
package org.signserver.server.cryptotokens;

import java.util.Properties;
import junit.framework.TestCase;
import org.junit.Test;
import org.signserver.common.CryptoTokenInitializationFailureException;

/**
 * Unit tests for the AzureKeyVaultCryptoToken.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class AzureKeyVaultCryptoTokenUnitTest extends TestCase {
    /**
     * Test that setting none of the required properties results in an
     * initialization failure mentioning missing properties.
     * @throws Exception 
     */
    @Test
    public void test01MissingRequiredProperties() throws Exception {
        final AzureKeyVaultCryptoToken instance = new AzureKeyVaultCryptoToken();

        try {
            instance.init(42, new Properties(), null);
        } catch (CryptoTokenInitializationFailureException ex) {
            assertEquals("Expected error message",
                         "Missing values for [KEY_VAULT_NAME, KEY_VAULT_CLIENT_ID, KEY_VAULT_TYPE]",
                         ex.getMessage());
        }
    }

    private void testWithMissingProperty(final String missingProperty)
            throws Exception {
        final AzureKeyVaultCryptoToken instance = new AzureKeyVaultCryptoToken();

        try {
            final Properties props = new Properties();

            props.setProperty(CryptoTokenHelper.PROPERTY_KEY_VAULT_NAME, "test-keyvault");
            props.setProperty(CryptoTokenHelper.PROPERTY_KEY_VAULT_CLIENT_ID ,
                              "dummy-client-id");
            props.setProperty(CryptoTokenHelper.PROPERTY_KEY_VAULT_TYPE,
                              "standard");
            props.remove(missingProperty);

            instance.init(42, props, null);
        } catch (CryptoTokenInitializationFailureException ex) {
            assertEquals("Expected error message",
                         "Missing value for " + missingProperty,
                         ex.getMessage());
        }
    }

    /**
     * Test that missing KEY_VAULT_NAME gives expected error message.
     *
     * @throws Exception 
     */
    @Test
    public void test02MissingKeyVaultName() throws Exception {
        testWithMissingProperty(CryptoTokenHelper.PROPERTY_KEY_VAULT_NAME);
    }

    /**
     * Test that missing KEY_VAULT_CLIENT_ID gives expected error message.
     *
     * @throws Exception 
     */
    @Test
    public void test03MissingKeyVaultClientID() throws Exception {
        testWithMissingProperty(CryptoTokenHelper.PROPERTY_KEY_VAULT_CLIENT_ID);
    }

    /**
     * Test that missing KEY_VAULT_TYPE gives expected error message.
     *
     * @throws Exception 
     */
    @Test
    public void test03MissingKeyVaultType() throws Exception {
        testWithMissingProperty(CryptoTokenHelper.PROPERTY_KEY_VAULT_TYPE);
    }

    /**
     * Test that setting an unknown key vault type results in an error.
     *
     * @throws Exception 
     */
    @Test
    public void test04UnknownKeyVaultType() throws Exception {
        final AzureKeyVaultCryptoToken instance = new AzureKeyVaultCryptoToken();

        try {
            final Properties props = new Properties();

            props.setProperty(CryptoTokenHelper.PROPERTY_KEY_VAULT_NAME, "test-keyvault");
            props.setProperty(CryptoTokenHelper.PROPERTY_KEY_VAULT_CLIENT_ID ,
                              "dummy-client-id");
            props.setProperty(CryptoTokenHelper.PROPERTY_PIN, "foo123");
            props.setProperty(CryptoTokenHelper.PROPERTY_KEY_VAULT_TYPE,
                              "non-existing-type");

            instance.init(42, props, null);
        } catch (CryptoTokenInitializationFailureException ex) {
            assertEquals("Expected error message",
                         "Unsupported KEY_VAULT_TYPE: non-existing-type, allowed values: [standard, premium]",
                         ex.getMessage());
        }
    }
}
