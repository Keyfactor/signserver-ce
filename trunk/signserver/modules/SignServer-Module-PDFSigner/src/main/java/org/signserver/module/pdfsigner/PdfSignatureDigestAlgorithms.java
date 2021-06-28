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

import java.util.Arrays;
import java.util.List;

/**
 * Class holding signature digest algorithms that can be used in PDF Signing.
 * 
 * @author Aziz Göktepe
 * @version $Id$
 */
public final class PdfSignatureDigestAlgorithms {

    public static final String SHA1 = "SHA1";
    public static final String SHA256 = "SHA256";
    public static final String SHA_256 = "SHA-256";
    public static final String SHA384 = "SHA384";
    public static final String SHA_384 = "SHA-384";
    public static final String SHA512 = "SHA512";
    public static final String SHA_512 = "SHA-512";
    public static final String RIPEMD160 = "RIPEMD160";

    public static final List<String> ALL_SUPPORTED_DIGEST_ALGORITHMS
            = Arrays.asList(SHA1, SHA256, SHA_256, SHA384, SHA_384, SHA512, SHA_512, RIPEMD160);

    private PdfSignatureDigestAlgorithms() {
    }

    /**
     * Tests if given digest algorithm is supported for PDF document signing.
     * 
     * @param digestAlgorithm The string representation of signature digest algorithm (ex: SHA-256)
     * 
     * @return true if algorithm is supported, false otherwise
     */
    public static boolean isSupported(String digestAlgorithm) {
        return ALL_SUPPORTED_DIGEST_ALGORITHMS.contains(digestAlgorithm);
    }
}
