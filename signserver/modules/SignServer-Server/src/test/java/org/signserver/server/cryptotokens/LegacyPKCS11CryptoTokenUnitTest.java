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

import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.signserver.common.CompileTimeSettings;
import org.signserver.common.CryptoTokenInitializationFailureException;

import java.nio.file.Path;
import java.util.Properties;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class LegacyPKCS11CryptoTokenUnitTest {

    /**
     * Test that no allowlist is configured for ATTRIBUTESFILE.
     */
    @Test
    public void test01MissingAllowlist() {
        LegacyPKCS11CryptoToken legacyPKCS11CryptoToken = new LegacyPKCS11CryptoToken();
        Properties properties = new Properties();
        properties.put("ATTRIBUTESFILE", "/path/something.cfg");

        CryptoTokenInitializationFailureException exceptionThrown = assertThrows("CryptoTokenInitializationFailureException",
                CryptoTokenInitializationFailureException.class, ()->legacyPKCS11CryptoToken.init(6100, properties, null));
        assertEquals("Missing allowlist configuration for ATTRIBUTESFILE", exceptionThrown.getMessage());

    }

    /**
     * Test that setting a path that is not in the allowlist results in an error.
     */
    @Test
    public void test02PathIsNotInAllowlist() {
        LegacyPKCS11CryptoToken legacyPKCS11CryptoToken = new LegacyPKCS11CryptoToken();

        CompileTimeSettings mockCompileTimeSettings = mock(CompileTimeSettings.class);
        when(mockCompileTimeSettings.getAttributesFilePathProperties()).thenReturn(Set.of(Path.of("/path/")));

        try (MockedStatic<CompileTimeSettings> mockedStatic = Mockito.mockStatic(CompileTimeSettings.class)) {
            mockedStatic.when(CompileTimeSettings::getInstance).thenReturn(mockCompileTimeSettings);

            Properties properties = new Properties();

            properties.put("ATTRIBUTESFILE", "/not/a/correct/path/");
            CryptoTokenInitializationFailureException exceptionThrown = assertThrows("CryptoTokenInitializationFailureException",
                    CryptoTokenInitializationFailureException.class, () -> legacyPKCS11CryptoToken.init(6102, properties, null));

            assertEquals("ATTRIBUTESFILE is not allowed", exceptionThrown.getMessage());
        }
    }
}
