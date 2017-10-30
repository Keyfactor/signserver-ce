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
     * Validate the length of client supplied hash digest against the length of specified digest algorithm.
     * @param suppliedHashDataLengthBytes to read from
     * @param configuredHashDigestAlgo to read from
     * @return boolean value
     */
    public static Boolean isSuppliedHashDigestLengthValid(final String configuredHashDigestAlgo, int suppliedHashDataLengthBytes) {
        Integer clientSpecifiedHashLengthBits = null;

        if (configuredHashDigestAlgo != null && !configuredHashDigestAlgo.isEmpty()) {
            clientSpecifiedHashLengthBits = getOutputSizeBitsFromDigestAlgorithmString(configuredHashDigestAlgo);
        }

        if (clientSpecifiedHashLengthBits != null) {
            int clientSpecifiedHashLengthBytes = clientSpecifiedHashLengthBits / 8;
            return (clientSpecifiedHashLengthBytes == suppliedHashDataLengthBytes);
        } else {
            return null;
        }
    }
    
    public static Integer getOutputSizeBitsFromDigestAlgorithmString(final String digestAlg) {
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
                return null;
        }
    }
}
