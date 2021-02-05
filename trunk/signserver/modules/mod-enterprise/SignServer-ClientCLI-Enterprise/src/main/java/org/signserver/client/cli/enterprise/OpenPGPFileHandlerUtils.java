/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.client.cli.enterprise;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.Locale;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.signserver.openpgp.utils.ClearSignedFileProcessorUtils;

/**
 * Utility functions for PGP-related file handlers (OpenPGP and dpkg-sig)
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class OpenPGPFileHandlerUtils {
    /**
     * Gets a PGP algorithm identifier given a string either representing an
     * algorithm name (such as "SHA-256"), or the string representation of the
     * integer algorithm value.
     * 
     * @param algorithmString String representing the algorithm
     * @return the algorithm ID
     */
    public static int getPGPAlgorithm(final String algorithmString) {
        final int algorithm;
        switch (algorithmString.toUpperCase(Locale.ENGLISH)) {
            case "SHA1":
            case "SHA-1":
                algorithm = HashAlgorithmTags.SHA1;
                break;
            case "SHA256":
            case "SHA-256":
                algorithm = HashAlgorithmTags.SHA256;
                break;
            case "SHA384":
            case "SHA-384":
                algorithm = HashAlgorithmTags.SHA384;
                break;
            case "SHA512":
            case "SHA-512":
                algorithm = HashAlgorithmTags.SHA512;
                break;
            default:
                // try to parse it as an integer value
                try {
                    algorithm = Integer.parseInt(algorithmString);
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Unsupported hash digest algorithm: " +
                                                       algorithmString);
                }
        }

        return algorithm;
    }

    public static byte[] getEncoded(final byte[] digest, final int keyAlgorithm,
                                    final int hashDigestAlgorithm)
            throws IOException {
        final byte[] encoded;
        if (keyAlgorithm == PublicKeyAlgorithmTags.RSA_SIGN ||
            keyAlgorithm == PublicKeyAlgorithmTags.RSA_GENERAL) {
            final byte[] modifierBytes = getModifierBytes(hashDigestAlgorithm);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(modifierBytes);
            baos.write(digest);
            encoded = baos.toByteArray();
        } else {
            encoded = digest;
        }

        return encoded;
    }

    /**
     * Get DER encoding of DigestInfo for given hash algorithm.
     * 
     * @param hashDigestAlgorithm
     * @return DER encoding of DigestInfo
     */
    private static byte[] getModifierBytes(final int hashDigestAlgorithm) {
        switch (hashDigestAlgorithm) {
            case HashAlgorithmTags.SHA1:
                return new byte[] {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b,
                                   0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
            case HashAlgorithmTags.SHA256:
                return new byte[] {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
                                   (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                                   0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
            case HashAlgorithmTags.SHA384:
                return new byte[] {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60,
                                   (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                                   0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
            case HashAlgorithmTags.SHA512:
                return new byte[] {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60,
                                   (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                                   0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
            default:
                // this shouldn̈́'t happen…
                throw new IllegalArgumentException("No known DER encoding of DigestInfo for supplied hash algorithm");
        }
    }
    
    public static void hashClearText(final PGPSignatureGenerator generator,
                                     final InputStream is)
            throws FileNotFoundException, IOException, SignatureException {
        ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
        int lookAhead = ClearSignedFileProcessorUtils.readInputLine(lineOut, is);
        ClearSignedFileProcessorUtils.processLine(generator, lineOut.toByteArray());
        if (lookAhead != -1) {
            do {
                lookAhead =
                        ClearSignedFileProcessorUtils.readInputLine(lineOut,
                                                                    lookAhead,
                                                                    is);

                generator.update((byte) '\r');
                generator.update((byte) '\n');

                ClearSignedFileProcessorUtils.processLine(generator,
                                                          lineOut.toByteArray());
            } while (lookAhead != -1);
        }
    }

    public static void processClearText(final ArmoredOutputStream aOut,
                                        final InputStream is,
                                        int hashDigestAlgorithm)
            throws FileNotFoundException, IOException, SignatureException {
        aOut.beginClearText(hashDigestAlgorithm);
        ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
        int lookAhead = ClearSignedFileProcessorUtils.readInputLine(lineOut, is);
        ClearSignedFileProcessorUtils.processLine(aOut, lineOut.toByteArray());
        if (lookAhead != -1) {
            do {
                lookAhead =
                        ClearSignedFileProcessorUtils.readInputLine(lineOut,
                                                                    lookAhead,
                                                                    is);

                ClearSignedFileProcessorUtils.processLine(aOut, lineOut.toByteArray());
            } while (lookAhead != -1);
        }

        // Add new line before signature if needed
        byte[] lastBytes = lineOut.toByteArray();
        if (lastBytes.length > 0 && (lastBytes[lastBytes.length - 1] != '\r' && lastBytes[lastBytes.length - 1] != '\n')) {
            aOut.write("\r\n".getBytes(StandardCharsets.US_ASCII));
        }

        aOut.endClearText();
    }
}
