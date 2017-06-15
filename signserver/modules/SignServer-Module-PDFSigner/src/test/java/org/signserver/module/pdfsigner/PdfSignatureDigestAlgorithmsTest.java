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
 * Unit tests for PdfSignatureDigestAlgorithms.
 * 
 * @author Aziz Göktepe
 * @version $Id$
 */
public class PdfSignatureDigestAlgorithmsTest {
    
    public PdfSignatureDigestAlgorithmsTest() {
    }

    /**
     * Tests that SHA1 256 384 512 and RPEMD160 algorithms are supported.
     */
    @Test
    public void shouldSupportSHA_1_256_384_512_RIPEDM160() {
        assertDigestAlgorithmIsSupported("SHA1");
        assertDigestAlgorithmIsSupported("SHA256");
        assertDigestAlgorithmIsSupported("SHA-256");
        assertDigestAlgorithmIsSupported("SHA384");
        assertDigestAlgorithmIsSupported("SHA-384");
        assertDigestAlgorithmIsSupported("SHA512");
        assertDigestAlgorithmIsSupported("SHA-512");
        assertDigestAlgorithmIsSupported("RIPEMD160");
    }
    
    /**
     * Tests that some non existent algorithm is not supported.
     */
    @Test
    public void shouldNotSupportFictitiousDigestAlgorithm() {
        boolean supported = PdfSignatureDigestAlgorithms.isSupported("HSA 256");
        assertFalse("We support fictitious Digest Algorithms ??", supported);
    }
    
    private void assertDigestAlgorithmIsSupported(String digestAlg) {
        boolean supported= PdfSignatureDigestAlgorithms.isSupported(digestAlg);
        assertTrue(digestAlg + " is not supported as PDF Digest Algorithm", supported);
    }
}
