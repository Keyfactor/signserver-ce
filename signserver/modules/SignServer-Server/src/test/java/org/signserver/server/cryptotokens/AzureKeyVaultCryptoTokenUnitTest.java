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
                         "Missing values for [KEY_VAULT_NAME, KEY_VAULT_CLIENT_ID, PIN, KEY_VAULT_TYPE]",
                         ex.getMessage());
        }
    }

    /**
     * Test that setting an unknown key vault type results in an error.
     *
     * @throws Exception 
     */
    @Test
    public void test02UnknownKeyVaultType() throws Exception {
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
