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
package org.signserver.module.openpgp.signer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.signserver.common.SignServerException;

/**
 * Utility methods for OpenPGP functionality.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class OpenPGPUtils {

    /**
     * Get the OpenPGP Key Algorithm ID given the provided certificate.
     *
     * @param x509Cert to get public key algorithm from
     * @return the OpenPGP Key Algorithm ID
     * @throws SignServerException
     */
    public static int getKeyAlgorithm(X509Certificate x509Cert) throws SignServerException {
        final int keyAlg;
        switch (x509Cert.getPublicKey().getAlgorithm()) {
            case "RSA":
                keyAlg = PublicKeyAlgorithmTags.RSA_SIGN;
                break;
            case "EC":
                keyAlg = PublicKeyAlgorithmTags.ECDSA;
                break;
            case "DSA":
                keyAlg = PublicKeyAlgorithmTags.DSA;
                break;
            default:
                throw new SignServerException("Unsupported key algorithm: " + x509Cert.getPublicKey().getAlgorithm());
        }
        return keyAlg;
    }

    /**
     * Get the OpenPGP Hash Algorithm ID from the provided signature name, hash
     * name or OpenPGP Hash Algorithm ID.
     *
     * @param signatureAlgorithm signature or hash algorithm name or numeric id
     * @return Numeric hash algorithm ID
     * @throws SignServerException in case the name is unknown or the integer can not be parsed
     */
    public static int getHashAlgorithm(final String signatureAlgorithm) throws SignServerException {
        // Check if it is already a nummeric value
        if (StringUtils.isNumeric(signatureAlgorithm)) {
            try {
                return Integer.parseInt(signatureAlgorithm);
            } catch (NumberFormatException ex) {
                throw new SignServerException("Unable to parse OpenPGP Hash Algorithm as nummeric value: " + ex.getMessage());
            }
        }

        // In case this is a signature algorithm of form HASHwithKEYALG
        String hash = signatureAlgorithm;
        int i = hash.indexOf("with");
        if (i == -1) {
            i = hash.indexOf("With");
        }
        if (i > 0) {
            hash = signatureAlgorithm.substring(0, i);
        }

        // Normalize the hash algorithm name
        hash = hash.replace("-", "");

        switch (hash) {
            case "SHA1":
                return HashAlgorithmTags.SHA1;
            case "MD2":
                return HashAlgorithmTags.MD2;
            case "MD5":
                return HashAlgorithmTags.MD5;
            case "RIPEMD160":
                return HashAlgorithmTags.RIPEMD160;
            case "SHA256":
                return HashAlgorithmTags.SHA256;
            case "SHA384":
                return HashAlgorithmTags.SHA384;
            case "SHA512":
                return HashAlgorithmTags.SHA512;
            case "SHA224":
                return HashAlgorithmTags.SHA224;
            case "TIGER":
                return HashAlgorithmTags.TIGER_192;
        default:
            throw new SignServerException("Unknown hash algorithm: " + hash);
        }
    }

    /**
     * Read public keys from the provided ASCII armored public key.
     *
     * @param publicKeyValue ASCII armored public key
     * @return list of PGP public keys
     * @throws IOException in case the provided key ring can not be parsed
     * @throws PGPException in case the provided key ring can not be parsed
     */
    public static List<PGPPublicKey> parsePublicKeys(final String publicKeyValue) throws IOException, PGPException {
        final ArrayList<PGPPublicKey> results = new ArrayList<>();
        try (InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(publicKeyValue.getBytes(StandardCharsets.US_ASCII)))) {
            final JcaPGPPublicKeyRingCollection pgpPub = new JcaPGPPublicKeyRingCollection(in);

            final Iterator<PGPPublicKeyRing> ringIterator = pgpPub.getKeyRings();
            while (ringIterator.hasNext()) {
                final PGPPublicKeyRing ring = ringIterator.next();
                final Iterator<PGPPublicKey> keyIterator = ring.getPublicKeys();
                while (keyIterator.hasNext()) {
                    final PGPPublicKey key = keyIterator.next();
                    if (key != null) {
                        results.add(key);
                    }
                }
            }
        }
        return results;
    }

    /**
     * Format the provided value as a Key ID (i.e. in hex and with leading zero
     * if needed).
     *
     * @param keyId value to encode
     * @return the Key ID in textual representation
     */
    public static String formatKeyID(final long keyId) {
        String result = String.format("%X", keyId);
        if (result.length() % 2 != 0) {
            result = "0" + result;
        }
        return result;
    }

    /**
     * Get the OpenPGP Hash Algorithm from its textual representation.
     *
     * @param digest in text-form
     * @return Hash Algorithm ID
     * @throws PGPException for unsupported input
     */
    public static int getDigestFromString(String digest) throws PGPException {
        switch (digest) {
            case "SHA1":
            case "SHA-1":
                return HashAlgorithmTags.SHA1;
            case "SHA256":
            case "SHA-256":
                return HashAlgorithmTags.SHA256;
            case "SHA384":
            case "SHA-384":
                return HashAlgorithmTags.SHA384;
            case "SHA224":
            case "SHA-224":
                return HashAlgorithmTags.SHA224;
            case "SHA512":
            case "SHA-512":
                return HashAlgorithmTags.SHA512;
        default:
            throw new PGPException("Unsupported OpenPGP Hash Algorithm");
        }
    }
}
