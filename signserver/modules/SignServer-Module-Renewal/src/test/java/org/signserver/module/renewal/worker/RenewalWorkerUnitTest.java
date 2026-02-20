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
package org.signserver.module.renewal.worker;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.signserver.common.CompileTimeSettings;
import org.signserver.common.WorkerConfig;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test cases for the error handling in RenewalWorker.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class RenewalWorkerUnitTest  {

    /**
     * Test that not setting a truststore type results in an error.
     */
    @Test
    public void test01NoTruststoreType()  {
        final List<String> fatalErrors = getFatalErrors(null, "dummypath", "foo123", null, "defaultKey", "http://ejbca/ws");
        
        assertTrue("Should contain error", fatalErrors.contains("Missing TRUSTSTORETYPE property"));
    }
    
    /**
     * Test that not setting either trustore path or value results in an error.
     */
    @Test
    public void test02NoTruststorePathOrTruststoreValue() {
        final List<String> fatalErrors = getFatalErrors("JKS", null, "foo123", null, "defaultKey", "http://ejbca/ws");
    
        assertTrue("Should contain error",
                fatalErrors.contains("Missing TRUSTSTOREPATH or TRUSTSTOREVALUE property"));
    }
    
    /**
     * Test that setting both truststore path and value results in an error.
     */
    @Test
    public void test03BothTruststorePathAndTruststoreValue() {
        final List<String> fatalErrors = getFatalErrors("JKS", "dummypath", "foo123", "DUMMYVALUE", "defaultKey", "http://ejbca/ws");
        
        assertTrue("Should contain error",
                fatalErrors.contains("Can not specify both TRUSTSTOREPATH and TRUSTSTOREVALUE property"));
    }

    /**
     * Test that not setting a truststore password results in an error.
     */
    @Test
    public void test04NoTruststorePassword() {
        final List<String> fatalErrors = getFatalErrors("JKS", "dummypath", null, null, "defaultKey", "http://ejbca/ws");
        
        assertTrue("Should contain error",
                fatalErrors.contains("Missing TRUSTSTOREPASSWORD property"));
    }
    
    /**
     * Test that truststore password is not required for PEM.
     */
    @Test
    public void test05NoTruststorePasswordPEM() {
        CompileTimeSettings mockCompileTimeSettings = mock(CompileTimeSettings.class);
        when(mockCompileTimeSettings.getTruststorePathProperties()).thenReturn(Set.of(Path.of("dummypath")));

        try (MockedStatic<CompileTimeSettings> mockedStatic = Mockito.mockStatic(CompileTimeSettings.class)) {
            mockedStatic.when(CompileTimeSettings::getInstance).thenReturn(mockCompileTimeSettings);
            final List<String> fatalErrors = getFatalErrors("PEM", "dummypath", null, null, "defaultKey", "http://ejbca/ws");

            assertTrue("Should contain no errors", fatalErrors.isEmpty());
        }
    }
    
    /**
     * Test that not setting EJBCA WS URL results in an error.
     * 
     */
    @Test
    public void test06NoEJBCAWSUrl() {
        final List<String> fatalErrors = getFatalErrors("JKS", "dummypath", "foo123", null, "defaultKey", null);
        
        assertTrue("Should contain error",
                fatalErrors.contains("Missing EJBCAWSURL property"));
    }
    
    /**
     * Test that not specifying DEFAULTKEY results in an error.
     * 
     */
    @Test
    public void test07NoDefaultKey() {
        final List<String> fatalErrors = getFatalErrors("JKS", "dummypath", "foo123", null, null, "http://ejbca/ws");
        
        assertTrue("Should contain error",
                fatalErrors.contains("Missing DEFAULTKEY property"));
    }

    /**
     * Test that setting the TRUSTSTOREPATH without an allowlist results in an error.
     *
     */
    @Test
    public void test08EmptyAllowlistForTruststorePath() {
        final List<String> fatalErrors = getFatalErrors("PEM", "dummypath", "foo123", null, "defaultKey", "http://ejbca/ws");

        assertEquals(1, fatalErrors.size());
        assertTrue("Should contain error",
                fatalErrors.contains("Missing allowlist configuration for TRUSTSTOREPATH"));
    }

    /**
     * Test that setting the TRUSTSTOREPATH to a value that is not in the configured allowlist results in an error.
     */
    @Test
    public void test09TruststorePathNotInAllowlist() {
        CompileTimeSettings mockCompileTimeSettings = mock(CompileTimeSettings.class);
        when(mockCompileTimeSettings.getTruststorePathProperties()).thenReturn(Set.of(Path.of("/test")));

        try (MockedStatic<CompileTimeSettings> mockedStatic = Mockito.mockStatic(CompileTimeSettings.class)) {
            mockedStatic.when(CompileTimeSettings::getInstance).thenReturn(mockCompileTimeSettings);
            final List<String> fatalErrors = getFatalErrors("PEM", "dummypath", "foo123", null, "defaultKey", "http://ejbca/ws");

            assertEquals(1, fatalErrors.size());
            assertTrue("Should contain error",
                    fatalErrors.contains("TRUSTSTOREPATH is not allowed"));
        }
    }

    /**
    * Test that setting the TRUSTSTOREPATH to a value that is in the configured allowlist is allowed.
    */
    @Test
    public void test10TruststorePathInAllowlistNoErrors() {
        CompileTimeSettings mockCompileTimeSettings = mock(CompileTimeSettings.class);
        when(mockCompileTimeSettings.getTruststorePathProperties()).thenReturn(Set.of(Path.of("/allowlist")));

        try (MockedStatic<CompileTimeSettings> mockedStatic = Mockito.mockStatic(CompileTimeSettings.class)) {
            mockedStatic.when(CompileTimeSettings::getInstance).thenReturn(mockCompileTimeSettings);
            final List<String> fatalErrors = getFatalErrors("PEM", "/allowlist/dummypath", null, null, "defaultKey", "http://ejbca/ws");
            assertTrue("Should contain no errors", fatalErrors.isEmpty());
        }
    }

    private List<String> getFatalErrors(final String truststoreType,
                                        final String truststorePath, final String truststorePassword,
                                        final String truststoreValue, final String defaultKey, final String ejbcawsUrl) {
        final WorkerConfig config = new WorkerConfig();

        if (truststoreType != null) {
            config.setProperty("TRUSTSTORETYPE", truststoreType);
        }

        if (truststorePath != null) {
            config.setProperty("TRUSTSTOREPATH", truststorePath);
        }

        if (truststorePassword != null) {
            config.setProperty("TRUSTSTOREPASSWORD", truststorePassword);
        }

        if (truststoreValue != null) {
            config.setProperty("TRUSTSTOREVALUE", truststoreValue);
        }

        if (defaultKey != null) {
            config.setProperty("DEFAULTKEY", defaultKey);
        }

        if (ejbcawsUrl != null) {
            config.setProperty("EJBCAWSURL", ejbcawsUrl);
        }

        final RenewalWorker worker = new RenewalWorker();

        worker.initInternal(4711, config, null, null);

        return worker.getLocalFatalErrors();
    }
}
