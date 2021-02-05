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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.util.Locale;
import java.util.Map;
import org.apache.log4j.Logger;
import org.bouncycastle.util.Arrays;
import org.signserver.client.cli.defaultimpl.DocumentSigner;
import org.signserver.client.cli.defaultimpl.DocumentSignerFactory;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;

/**
 * Java security provider accessing an ApkHashSigner to perform crypto
 * operations server-side.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ApkProvider extends Provider {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ApkProvider.class);

    public static final String NAME = "Apk";

    /**
     * Padding bytes for the supported hash functions, as defined in the 
     * PKCS #1 RSA Cryptography Specifications RFC (3447).
     * https://tools.ietf.org/html/rfc3447#page-43
     */
    static final byte[] RSA_SHA1_MODIFIER_BYTES = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
    static final byte[] RSA_SHA256_MODIFIER_BYTES = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    static final byte[] RSA_SHA384_MODIFIER_BYTES = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
    static final byte[] RSA_SHA512_MODIFIER_BYTES = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

    @SuppressWarnings("deprecation") // we need to support JDK 8 for now
    public ApkProvider() {
        super(NAME, 0.1, "Apk Provider");
        putServices();
    }

    private void putServices() {
        putService(new ApkSigningService(this, "Signature", "SHA1withRSA", ApkSignature.class.getName()));
        putService(new ApkSigningService(this, "Signature", "SHA256withRSA", ApkSignature.class.getName()));
        putService(new ApkSigningService(this, "Signature", "SHA384withRSA", ApkSignature.class.getName()));
        putService(new ApkSigningService(this, "Signature", "SHA512withRSA", ApkSignature.class.getName()));
        putService(new ApkSigningService(this, "Signature", "SHA1withECDSA", ApkSignature.class.getName()));
        putService(new ApkSigningService(this, "Signature", "SHA224withECDSA", ApkSignature.class.getName()));
        putService(new ApkSigningService(this, "Signature", "SHA256withECDSA", ApkSignature.class.getName()));
        putService(new ApkSigningService(this, "Signature", "SHA384withECDSA", ApkSignature.class.getName()));
        putService(new ApkSigningService(this, "Signature", "SHA512withECDSA", ApkSignature.class.getName()));
    }

    private static class ApkService extends Service {
        private static final Class[] paramTypes =
            { Provider.class, String.class };

        ApkService(final Provider provider, final String type,
                   final String algorithm, final String className) {
            super(provider, type, algorithm, className, null, null);
        }

        @Override
        public Object newInstance(final Object param)
                throws NoSuchAlgorithmException {
            try {
                final Class clazz;
                final Provider provider = getProvider();
                final ClassLoader loader = provider.getClass().getClassLoader();
                if (loader == null) {
                    clazz = Class.forName(getClassName());
                } else {
                    clazz = loader.loadClass(getClassName());
                }
                final Constructor cons = clazz.getConstructor(paramTypes);
                final Object obj =
                        cons.newInstance(new Object[] { provider,
                                                        getAlgorithm() });
                return obj;
            } catch (Exception e) {
                LOG.debug("Exception", e);
                throw new NoSuchAlgorithmException("Could not instantiate service", e);
            }
        }
    }

    private static final class ApkSigningService extends ApkService {
        
        public ApkSigningService(Provider provider, String type, String algorithm, String className) {
            super(provider, type, algorithm, className);
        }

        public ApkSigningService(Provider provider, String alg) {
            super(provider, null, alg, null);
        }

        @Override
        public boolean supportsParameter(Object parameter) {
            LOG.debug("supportsParameter: " + parameter.getClass().getName());
            return parameter instanceof ApkPrivateKey;
        }
    }

    final static class ApkSignature extends SignatureSpi {

        private ApkPrivateKey privateKey;
        private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private final String alg;

        public ApkSignature(Provider prov, String alg) {
            super();
            this.alg = alg;
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            this.privateKey = (ApkPrivateKey) privateKey;
        }

        @Override
        protected void engineUpdate(byte b) throws SignatureException {
            buffer.write(b);
        }

        @Override
        protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
            buffer.write(b, off, len);
        }

        @Override
        protected byte[] engineSign() throws SignatureException {
            final DocumentSigner signer;
            final DocumentSignerFactory signerFactory = privateKey.getSignerFactory();
            final Map<String, Object> requestContext = privateKey.getRequestContext();
            final String workerName = privateKey.getWorkerName();
            final int workerId = privateKey.getWorkerId();
            final Map<String, String> metadata = privateKey.getMetadata();
            
            if (workerName == null) {
                signer = signerFactory.createSigner(workerId, 
                                                    metadata,
                                                    true, true, "APK");
            } else {
                signer = signerFactory.createSigner(workerName,
                                                    metadata,
                                                    true, true, "APK");
            }

            
            
            try {
                final byte[] hash = getHashedMessage(buffer.toByteArray());
                final ByteArrayInputStream bis = new ByteArrayInputStream(hash);
                final ByteArrayOutputStream bos = new ByteArrayOutputStream();

                signer.sign(bis, hash.length, bos, requestContext);

                return bos.toByteArray();
            } catch (IllegalRequestException | CryptoTokenOfflineException |
                     SignServerException | IOException | NoSuchAlgorithmException e) {
                throw new SignatureException(e);
            }
        }

        private byte[] getHashedMessage(final byte[] data)
                throws NoSuchAlgorithmException {
            final String digestName = getDigestName();
            final MessageDigest md = MessageDigest.getInstance(digestName);
            final byte[] digest = md.digest(data);

            if (alg.toUpperCase(Locale.ENGLISH).endsWith("RSA")) {
                switch (digestName) {
                    case "SHA1":
                        return Arrays.concatenate(RSA_SHA1_MODIFIER_BYTES, digest);
                    case "SHA256":
                        return Arrays.concatenate(RSA_SHA256_MODIFIER_BYTES, digest);
                    case "SHA384":
                        return Arrays.concatenate(RSA_SHA384_MODIFIER_BYTES, digest);
                    case "SHA512":
                        return Arrays.concatenate(RSA_SHA512_MODIFIER_BYTES, digest);
                    default:
                        throw new IllegalArgumentException("No padding defined for RSA: " + digestName);
                }
            } else if (alg.toUpperCase(Locale.ENGLISH).endsWith("ECDSA")) {
                return digest;
            } else {
                throw new IllegalArgumentException("Unsupported key algorithm for: " + alg);
            }
        }

        private String getDigestName() {
            if (alg.toUpperCase(Locale.ENGLISH).endsWith("WITHRSA")) {
                return alg.substring(0, alg.length() - "withRSA".length());
            } else if (alg.toUpperCase(Locale.ENGLISH).endsWith("WITHECDSA")) {
                return alg.substring(0, alg.length() - "withECDSA".length());
            } else {
                throw new IllegalArgumentException("Unsupported algorithm: " + alg);
            }
        }
        
        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected Object engineGetParameter(String param) throws InvalidParameterException {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    }
}
