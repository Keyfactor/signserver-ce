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
package org.signserver.module.pdfsigner;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit tests for PdfVersionCompatibilityChecker.
 * 
 * @author Aziz Göktepe
 * @version $Id$
 */
public class PdfVersionCompatibilityCheckerTest {
    
    public PdfVersionCompatibilityCheckerTest() {
    }

    /**
     * Tests that version upgrade is required for SHA-256 when PDF version is 0.
     */
    @Test
    public void versionUpgradeRequiredForSha256_PdfVersionIs_0() {
        PdfVersionCompatibilityChecker checker = new PdfVersionCompatibilityChecker("0", "SHA-256");
        boolean upgradeRequired = checker.isVersionUpgradeRequired();
        assertTrue(upgradeRequired);
    }
    
    /**
     * Tests that version upgrade is not required for SHA-256 when PDF version is 6.
     */
    @Test
    public void versionUpgradeNotRequiredForSha256_PdfVersionIs_6() {
        PdfVersionCompatibilityChecker checker = new PdfVersionCompatibilityChecker("6", "SHA-256");
        boolean upgradeRequired = checker.isVersionUpgradeRequired();
        assertFalse(upgradeRequired);
    }
    
    /**
     * Tests that version upgrade is required for SHA-256 when PDF version is non-numeric (can't parse).
     */
    @Test
    public void versionUpgradeRequiredForSha256_PdfVersionIs_NotNumeric() {
        PdfVersionCompatibilityChecker checker = new PdfVersionCompatibilityChecker("XXXX", "SHA-256");
        boolean upgradeRequired = checker.isVersionUpgradeRequired();
        assertTrue(upgradeRequired);
    }
    
    /**
     * Tests that version upgrade is required for SHA-384 when PDF version is 6.
     */
    @Test
    public void versionUpgradeRequiredForSha384_PdfVersionIs_6() {
        PdfVersionCompatibilityChecker checker = new PdfVersionCompatibilityChecker("6", "SHA-384");
        boolean upgradeRequired = checker.isVersionUpgradeRequired();
        assertTrue(upgradeRequired);
    }

    /**
     * Tests that version upgrade is not required for SHA-384 when PDF version is 7.
     */
    @Test
    public void versionUpgradeNotRequiredForSha384_PdfVersionIs_7() {
        PdfVersionCompatibilityChecker checker = new PdfVersionCompatibilityChecker("7", "SHA-384");
        boolean upgradeRequired = checker.isVersionUpgradeRequired();
        assertFalse(upgradeRequired);
    }
    
    /**
     * Tests that minimum PDF version required for applying SHA-1 is 0.
     */
    @Test
    public void minimumVersionForSHA1Is0() {
        PdfVersionCompatibilityChecker checker = new PdfVersionCompatibilityChecker("0", "SHA1");
        int minVer = checker.getMinimumCompatiblePdfVersion();
        assertEquals(0, minVer);
    }
    
    /**
     * Tests that minimum PDF version required for applying SHA-256 is 6.
     */
    @Test
    public void minimumVersionForSHA256Is6() {
        PdfVersionCompatibilityChecker checker = new PdfVersionCompatibilityChecker("0", "SHA-256");
        int minVer = checker.getMinimumCompatiblePdfVersion();
        assertEquals(6, minVer);
    }
    
    /**
     * Tests that minimum PDF version required for applying SHA-512 is 7.
     */
    @Test
    public void minimumVersionForSHA512Is7() {
        PdfVersionCompatibilityChecker checker = new PdfVersionCompatibilityChecker("0", "SHA512");
        int minVer = checker.getMinimumCompatiblePdfVersion();
        assertEquals(7, minVer);
    }
    
    /**
     * Tests that given some unknown digest algorithm retrieval of minimum required PDF version (to apply that algorithm) throws exception.
     * 
     * @throws IllegalArgumentException 
     */
    @Test(expected = IllegalArgumentException.class)
    public void minimumVersionCannotBeRetrievedForUnknownDigestAlgorithm() {
        PdfVersionCompatibilityChecker checker = new PdfVersionCompatibilityChecker("0", "HSA 223");
        checker.getMinimumCompatiblePdfVersion();
    }
}
