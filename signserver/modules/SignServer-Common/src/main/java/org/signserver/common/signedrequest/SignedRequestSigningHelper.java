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
package org.signserver.common.signedrequest;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultJwtBuilder;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecureDigestAlgorithm;
import io.jsonwebtoken.security.SignatureException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.common.RequestContext;

/**
 * Helper doing as much of the stuff for the signed request as possible.
 *
 * Verification is not included here but it is typically implemented in a
 * corresponding SignedRequestVerifyingHelper.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SignedRequestSigningHelper {

    private static final Logger LOG = Logger.getLogger(SignedRequestSigningHelper.class);

    public static final String METADATA_PROPERTY_SIGNED_REQUEST = "SIGNED_REQUEST";

    public static final String TYPE = "http://signserver.org/specs/signedrequest/1.0";

    /**
     * Adds the SIGNED_REQUEST request metadata to the passed in metadata
     * 
     * @param digestAlgorithm the digest algorithm used for data and to be used for the other fields
     * @param digest the digest
     * @param metadata the metadata
     * @param fileName the file name (if any)
     * @param workerName the worker name (if any)
     * @param workerId the worker ID (if any)
     * @param signatureAlgorithm the algorithm to use
     * @param privateKey private key to use for signing
     * @param certChain cert chain for the signer
     * @throws SignedRequestException in case of failure creating the signature
     */
    public static void addRequestSignature(final String digestAlgorithm,
                                           final byte[] digest,
                                           final Map<String, String> metadata,
                                           final String fileName,
                                           final String workerName,
                                           final Integer workerId,
                                           final String signatureAlgorithm,
                                           final PrivateKey privateKey,
                                           final List<Certificate> certChain,
                                           final Provider provider)
            throws SignedRequestException {
        final String signature =
                SignedRequestSigningHelper.createSignedRequest(digestAlgorithm,
                                                               digest, metadata,
                                                               fileName,
                                                               workerName,
                                                               workerId,
                                                               privateKey,
                                                               signatureAlgorithm,
                                                               provider, certChain);
        metadata.put(SignedRequestSigningHelper.METADATA_PROPERTY_SIGNED_REQUEST,
                     signature);
    }
    
    /**
     * Constructs the SIGNED_REQUEST request metadata property value.
     *
     * @param digestAlgorithm the digest algorithm used for data and to be used for the other fields
     * @param requestDataDigest the digest
     * @param metadata the metadata
     * @param fileName the file name field (if any)
     * @param workerName the worker name field (if any)
     * @param workerId the worker id field (if any(
     * @param signKey private key to sign with
     * @param signatureAlgorithm the algorithm to use
     * @param provider provider for the signature
     * @param certificateChain for the signer
     * @return the String encoding of the SIGNED_REQUEST property
     * @throws SignedRequestException in case of failure creating the signature
     */
    public static String createSignedRequest(String digestAlgorithm, byte[] requestDataDigest, Map<String, String> metadata, String fileName, String workerName, Integer workerId, PrivateKey signKey, String signatureAlgorithm, Provider provider, List<Certificate> certificateChain) throws SignedRequestException {
        try {
            LOG.debug(">createSignedRequest");
            return createSignedJwt(createContentToBeSigned(digestAlgorithm, requestDataDigest, metadata, fileName, workerName, workerId),
                                   signKey, certificateChain.get(0).getPublicKey(), signatureAlgorithm,
                                   provider, certificateChain);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | IOException | CertificateEncodingException ex) {
            throw new SignedRequestException("Failed to sign signature request", ex);
        }
    }


    private static String createSignedJwt(Properties properties, PrivateKey signKey, PublicKey publicKey, String signatureAlgorithm, Provider provider, List<Certificate> certificateChain) throws SignedRequestException, CertificateEncodingException {
        LOG.debug(">createSignedJwt");

        final JwtBuilder builder = new DefaultJwtBuilder();
        /* special case for the Sun PKCS11 provider, otherwise use default
         * instead of the one from KeyStoreOptions in the P12 case (as the
         * provider is then "SUN"
         */
        final PrivateKey signPrivKey =
                "SunPKCS11".equals(provider.getName()) ?
                Keys.builder((PrivateKey) signKey).provider(provider).build() :
                signKey;
        final SignatureAlgorithm sigAlg =
                signatureAlgorithmForJcaName(signatureAlgorithm);
        final SecureDigestAlgorithm<?, ?> digAlg = Jwts.SIG.get().forKey(sigAlg.name());
        
        builder.setHeaderParam("typ", TYPE)
               .setHeaderParam("x5c", convertChain(certificateChain))
               .addClaims(convertPropertiesToClaims(properties))
               .signWith(signPrivKey, (SecureDigestAlgorithm<? super Key, ?>) digAlg);

        return builder.compact();
    }

    private static SignatureAlgorithm signatureAlgorithmForJcaName(String algorithm) {
        for (SignatureAlgorithm alg : SignatureAlgorithm.values()) {
            if (alg.getJcaName() != null && alg.getJcaName().equalsIgnoreCase(algorithm)) {
                return alg;
            }
        }

        throw new SignatureException("Unsupported signature algorithm '" + algorithm + "'");
    }
    
    private static List<String> convertChain(final List<Certificate> chain)
            throws CertificateEncodingException {
        final List<String> result = new LinkedList<>();

        for (final Certificate cert : chain) {
            result.add(Base64.toBase64String(cert.getEncoded()));
        }

        return result;
    }

    private static Map<String, Object> convertPropertiesToClaims(final Properties properties) {
        final Map<String, Object> result = new HashMap<>();
        
        for (final String key : properties.stringPropertyNames()) {
            result.put(key, properties.get(key));
        }

        return result;
    }
        
    private static Properties createContentToBeSigned(String digestAlgorithm, byte[] requestDataDigest, Map<String, String> metadata, String fileName, String workerName, Integer workerId) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
        Properties properties = new Properties();
       
        properties.put("data", Hex.toHexString(requestDataDigest));
        ArrayList<String> metaKeys = new ArrayList<>(metadata.keySet());
        for (String metaKey : metaKeys) {
            if (!metaKey.equals(METADATA_PROPERTY_SIGNED_REQUEST)) {
                properties.put("meta." + metaKey, Hex.toHexString(hash(metadata.get(metaKey), digestAlgorithm)));
            }
        }
        if (fileName != null) {
            properties.put(RequestContext.FILENAME, Hex.toHexString(hash(fileName, digestAlgorithm)));
        }

        if (workerName != null) {
            properties.put("workerName", Hex.toHexString(hash(workerName, digestAlgorithm)));
        }
        if (workerId != null) {
            properties.put("workerId", Hex.toHexString(hash(String.valueOf(workerId), digestAlgorithm)));
        }
        
        return properties;
    }
    
    public static byte[] hash(String value, String digestAlgorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest md = MessageDigest.getInstance(digestAlgorithm, "BC");
        
        return md.digest(value == null ? new byte[0] : value.getBytes(StandardCharsets.UTF_8));
    }
    
    /**
     * Get the hash algorithm to use based on the signature algorithm in the JWS.
     * Note: This implementation assumes the SHA-2 family is used and the number in the
     * algorithm indicates the digest bit length. When support for other digest
     * algorithms like SHA3 is introduced this code need to be updated to handle those
     * differently.
     * @param jws to get the signature algorithm from
     * @return the JCA digest algorithm name corresponding to the signature algorithm
     */
    public static String getDigestAlgorithm(final Jws<Claims> jws) {
        SignatureAlgorithm alg = SignatureAlgorithm.forName(jws.getHeader().getAlgorithm());
        return "SHA-" + alg.getValue().substring(2);
    }

}
