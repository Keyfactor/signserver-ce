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
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultJwtBuilder;
import io.jsonwebtoken.impl.crypto.DefaultJwtSigner;
import io.jsonwebtoken.impl.crypto.EllipticCurveProvider;
import io.jsonwebtoken.impl.crypto.JwtSigner;
import io.jsonwebtoken.impl.crypto.MacSigner;
import io.jsonwebtoken.impl.crypto.RsaProvider;
import io.jsonwebtoken.impl.crypto.Signer;
import io.jsonwebtoken.impl.crypto.SignerFactory;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.SignatureException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
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
                                           final List<Certificate> certChain)
            throws SignedRequestException {
        final String signature =
                SignedRequestSigningHelper.createSignedRequest(digestAlgorithm,
                                                               digest, metadata,
                                                               fileName,
                                                               workerName,
                                                               workerId,
                                                               privateKey,
                                                               signatureAlgorithm,
                                                               null, certChain);
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

    private static Key packKey(PrivateKey privateKey, PublicKey publicKey) {
        if (!(privateKey instanceof RSAKey) && !(privateKey instanceof ECKey)) {
            if (publicKey instanceof RSAPublicKey) {
                return new PackedRsaPrivateKey(privateKey, (RSAPublicKey) publicKey);
            } else if (publicKey instanceof ECPublicKey) {
                return new PackedEcPrivateKey(privateKey, (ECPublicKey) publicKey);
            }
        }
        return privateKey;
    }
    
    private interface PackedPrivateKey {
        public PrivateKey getPacked();
    }
    
    private static class PackedRsaPrivateKey implements PrivateKey, RSAKey, PackedPrivateKey {

        private final PrivateKey packed;
        private final RSAPublicKey publicKey;

        public PackedRsaPrivateKey(PrivateKey packed, RSAPublicKey publicKey) {
            this.packed = packed;
            this.publicKey = publicKey;
        }
        
        @Override
        public BigInteger getModulus() {
            return publicKey.getModulus();
        }

        @Override
        public String getAlgorithm() {
            return packed.getAlgorithm();
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return null;
        }

        @Override
        public PrivateKey getPacked() {
            return packed;
        }
        
    }
    
    private static class PackedEcPrivateKey implements PrivateKey, ECKey, PackedPrivateKey {

        private final PrivateKey packed;
        private final ECPublicKey publicKey;

        public PackedEcPrivateKey(PrivateKey packed, ECPublicKey publicKey) {
            this.packed = packed;
            this.publicKey = publicKey;
        }

        @Override
        public ECParameterSpec getParams() {
            return publicKey.getParams();
        }

        @Override
        public String getAlgorithm() {
            return packed.getAlgorithm();
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return null;
        }

        @Override
        public PrivateKey getPacked() {
            return packed;
        }
        
    }

    private static class RsaSigner extends RsaProvider implements Signer {

        public RsaSigner(SignatureAlgorithm alg, Key key) {
            super(alg, key);
            // https://github.com/jwtk/jjwt/issues/68
            // Instead of checking for an instance of RSAPrivateKey, check for PrivateKey and RSAKey:
            if (!(key instanceof PrivateKey && "RSA".equals(key.getAlgorithm()))) {
                String msg = "RSA signatures must be computed using an RSA PrivateKey.  The specified key of type " +
                             key.getClass().getName() + " is not an RSA PrivateKey.";
                throw new IllegalArgumentException(msg);
            }
        }

        @Override
        public byte[] sign(byte[] data) {
            try {
                return doSign(data);
            } catch (InvalidKeyException e) {
                throw new SignatureException("Invalid RSA PrivateKey. " + e.getMessage(), e);
            } catch (java.security.SignatureException e) {
                throw new SignatureException("Unable to calculate signature using RSA PrivateKey. " + e.getMessage(), e);
            }
        }

        protected byte[] doSign(byte[] data) throws InvalidKeyException, java.security.SignatureException {
            PrivateKey privateKey = (PrivateKey)key;
            Signature sig = createSignatureInstance();
            sig.initSign(privateKey);
            sig.update(data);
            return sig.sign();
        }
    }

    private static class EcSigner extends EllipticCurveProvider implements Signer {
        public EcSigner(SignatureAlgorithm alg, Key key) {
            super(alg, key);
            if (!(key instanceof PrivateKey && ("EC".equals(key.getAlgorithm()) || "ECDSA".equals(key.getAlgorithm())))) {
                String msg = "Elliptic Curve signatures must be computed using an EC PrivateKey.  The specified key of " +
                             "type " + key.getClass().getName() + " is not an EC PrivateKey.";
                throw new IllegalArgumentException(msg);
            }
        }

        @Override
        public byte[] sign(byte[] data) {
            try {
                return doSign(data);
            } catch (InvalidKeyException e) {
                throw new SignatureException("Invalid Elliptic Curve PrivateKey. " + e.getMessage(), e);
            } catch (java.security.SignatureException e) {
                throw new SignatureException("Unable to calculate signature using Elliptic Curve PrivateKey. " + e.getMessage(), e);
            } catch (JwtException e) {
                throw new SignatureException("Unable to convert signature to JOSE format. " + e.getMessage(), e);
            }
        }

        protected byte[] doSign(byte[] data) throws InvalidKeyException, java.security.SignatureException, JwtException {
            PrivateKey privateKey = (PrivateKey)key;
            Signature sig = createSignatureInstance();
            sig.initSign(privateKey);
            sig.update(data);
            return transcodeSignatureToConcat(sig.sign(), getSignatureByteArrayLength(alg));
        }
        
    }

    private static String createSignedJwt(Properties properties, PrivateKey signKey, PublicKey publicKey, String signatureAlgorithm, Provider provider, List<Certificate> certificateChain) throws SignedRequestException, CertificateEncodingException {
        LOG.debug(">createSignedJwt");

        final JwtBuilder builder = new DefaultJwtBuilder() {
            @Override
            protected JwtSigner createSigner(SignatureAlgorithm alg, Key key) {
                return new DefaultJwtSigner(new SignerFactory() {
                    @Override
                    public Signer createSigner(SignatureAlgorithm alg, Key key) {
                        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
                        Assert.notNull(key, "Signing Key cannot be null.");

                        final Key keyToUse;
                        if (key instanceof PackedPrivateKey) {
                            keyToUse = ((PackedPrivateKey) key).getPacked();
                        } else {
                            keyToUse = key;
                        }
                        
                        switch (alg) {
                            
                            case HS256:
                            case HS384:
                            case HS512:
                                return new MacSigner(alg, keyToUse);
                            case RS256:
                            case RS384:
                            case RS512:
                            case PS256:
                            case PS384:
                            case PS512:
                                return new RsaSigner(alg, keyToUse);
                            case ES256:
                            case ES384:
                            case ES512:
                                return new EcSigner(alg, keyToUse);
                            default:
                                throw new IllegalArgumentException("The '" + alg.name() + "' algorithm cannot be used for signing.");
                        }
                    } 
                }, alg, key, Encoders.BASE64URL);
            }
            
        };
        
        builder.setHeaderParam("typ", TYPE)
               .setHeaderParam("x5c", convertChain(certificateChain))
               .addClaims(convertPropertiesToClaims(properties))
               .signWith(packKey(signKey, publicKey),
                         signatureAlgorithmForJcaName(signatureAlgorithm));

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
