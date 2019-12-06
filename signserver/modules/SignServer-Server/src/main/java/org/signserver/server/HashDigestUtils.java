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
package org.signserver.server;

/**
 * Helper method for validating Hash Digest.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class HashDigestUtils {
    /**
     * Validate the length of client supplied hash digest against the length of digest algorithm.
     * @param hashDigestAlgo client specified or server side configured hashDigestAlgorithm
     * @param suppliedHashDataLengthBytes length of client supplied hash digest in Bytes
     * @return boolean value indicating whether hash digest length valid or not
     */
    public static boolean isSuppliedHashDigestLengthValid(final String hashDigestAlgo, int suppliedHashDataLengthBytes) {

        if (hashDigestAlgo != null && !hashDigestAlgo.trim().isEmpty()) {
            int clientSpecifiedHashLengthBytes = getOutputSizeBitsFromDigestAlgorithmString(hashDigestAlgo) / 8;
            return (clientSpecifiedHashLengthBytes == suppliedHashDataLengthBytes);
        }

        return false;
    }
    
    /**
     * Returns the length of output digest in bits for provided digest algorithm.     * 
     * @param digestAlg digest algorithm 
     * @return digest output length in bits
     */
    public static int getOutputSizeBitsFromDigestAlgorithmString(final String digestAlg) {
        switch (digestAlg.toUpperCase()) {
            case "MD5":
            case "MD-5":
                return 128;
            case "SHA1":
            case "SHA-1":
                return 160;
            case "SHA224":
            case "SHA-224":
                return 224;
            case "SHA256":
            case "SHA-256":
                return 256;
            case "SHA384":
            case "SHA-384":
                return 384;
            case "SHA512":
            case "SHA-512":
                return 512;
            default:
                throw new IllegalArgumentException("Invalid Digest Algorithm");
        }
    }
}
