/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.p11ng.common.provider;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.apache.log4j.Logger;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.AlgorithmParametersSpi.PSS;
import org.pkcs11.jacknji11.CKG;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.ULong;
import org.signserver.server.cryptotokens.MechanismNames;
import static org.signserver.server.cryptotokens.MechanismNames.CKM_PARAMS;

/**
 * Provider using JackNJI11.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class JackNJI11Provider extends Provider {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(JackNJI11Provider.class);

    public static final String NAME = "JackNJI11";
    
    private final static Map<String, Long> DIGEST_NAME_TO_CKM_MAP = new HashMap<>();
    private final static Map<String, Long> DIGEST_NAME_TO_CKG_MAP = new HashMap<>();

    static {
        // Map betwen Java digest algorithm name and mechanism
        DIGEST_NAME_TO_CKM_MAP.put("SHA1", CKM.SHA_1);
        DIGEST_NAME_TO_CKM_MAP.put("SHA-1", CKM.SHA_1);
        DIGEST_NAME_TO_CKM_MAP.put("SHA256", CKM.SHA256);
        DIGEST_NAME_TO_CKM_MAP.put("SHA-256", CKM.SHA256);
        DIGEST_NAME_TO_CKM_MAP.put("SHA384", CKM.SHA384);
        DIGEST_NAME_TO_CKM_MAP.put("SHA-384", CKM.SHA384);
        DIGEST_NAME_TO_CKM_MAP.put("SHA512", CKM.SHA512);
        DIGEST_NAME_TO_CKM_MAP.put("SHA-512", CKM.SHA512);
        
        // Map between Java digest algorithm name and mask generation mechanism
        DIGEST_NAME_TO_CKG_MAP.put("SHA1", CKG.MGF1_SHA1);
        DIGEST_NAME_TO_CKG_MAP.put("SHA-1", CKG.MGF1_SHA1);
        DIGEST_NAME_TO_CKG_MAP.put("SHA256", CKG.MGF1_SHA256);
        DIGEST_NAME_TO_CKG_MAP.put("SHA-256", CKG.MGF1_SHA256);
        DIGEST_NAME_TO_CKG_MAP.put("SHA384", CKG.MGF1_SHA384);
        DIGEST_NAME_TO_CKG_MAP.put("SHA-384", CKG.MGF1_SHA384);
        DIGEST_NAME_TO_CKG_MAP.put("SHA512", CKG.MGF1_SHA512);
        DIGEST_NAME_TO_CKG_MAP.put("SHA-512", CKG.MGF1_SHA512);
    }

    @SuppressWarnings("OverridableMethodCallInConstructor")
    public JackNJI11Provider() {
        super(NAME, 0.31, "JackNJI11 Provider");

        putService(new MySigningService(this, "Signature", "NONEwithRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "MD5withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA1withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA224withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA256withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA384withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA512withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "NONEwithDSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA1withDSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "NONEwithRSAandMGF1", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA1withRSAandMGF1", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA256withRSAandMGF1", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA384withRSAandMGF1", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA512withRSAandMGF1", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "NONEwithRSASSA-PSS", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA1withRSASSA-PSS", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA256withRSASSA-PSS", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA384withRSASSA-PSS", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA512withRSASSA-PSS", MySignature.class.getName()));
        putService(new MySigningService(this, "MessageDigest", "SHA256", MyMessageDigiest.class.getName()));
        putService(new MySigningService(this, "MessageDigest", "SHA384", MyMessageDigiest.class.getName()));
        putService(new MySigningService(this, "MessageDigest", "SHA512", MyMessageDigiest.class.getName()));
        putService(new MySigningService(this, "AlgorithmParameters", "PSS", MyAlgorithmParameters.class.getName()));
    }

    private static class MyService extends Service {

        private static final Class[] paramTypes = {Provider.class, String.class};

        MyService(Provider provider, String type, String algorithm,
                String className) {
            super(provider, type, algorithm, className, null, null);
        }

        @Override
        public Object newInstance(Object param) throws NoSuchAlgorithmException {
            try {
                // get the Class object for the implementation class
                Class clazz;
                Provider provider = getProvider();
                ClassLoader loader = provider.getClass().getClassLoader();
                if (loader == null) {
                    clazz = Class.forName(getClassName());
                } else {
                    clazz = loader.loadClass(getClassName());
                }
                // fetch the (Provider, String) constructor
                Constructor cons = clazz.getConstructor(paramTypes);
                // invoke constructor and return the SPI object
                Object obj = cons.newInstance(new Object[] {provider, getAlgorithm()});
                return obj;
            } catch (ClassNotFoundException | IllegalAccessException | IllegalArgumentException | InstantiationException | NoSuchMethodException | SecurityException | InvocationTargetException e) {
                LOG.error("Could not instantiate service", e);
                throw new NoSuchAlgorithmException("Could not instantiate service", e);
            }
        }
    }

    private static class MySigningService extends MyService {

        MySigningService(Provider provider, String type, String algorithm,
                String className) {
            super(provider, type, algorithm, className);
        }

        // we override supportsParameter() to let the framework know which
        // keys we can support. We support instances of MySecretKey, if they
        // are stored in our provider backend, plus SecretKeys with a RAW encoding.
        @Override
        public boolean supportsParameter(Object obj) {
            if (obj instanceof NJI11StaticSessionPrivateKey == false
                    && obj instanceof NJI11ReleasebleSessionPrivateKey == false) {
                if (LOG.isDebugEnabled()) {
                    final StringBuilder sb = new StringBuilder();
                    sb.append("Not our object:\n")
                            .append(obj)
                            .append(", classloader: ")
                            .append(obj.getClass().getClassLoader())
                            .append(" (").append(this.getClass().getClassLoader().hashCode()).append(")")
                            .append("\n");
                    sb.append("We are:\n")
                            .append(this)
                            .append(", classloader: ")
                            .append(this.getClass().getClassLoader())
                            .append(" (").append(this.getClass().getClassLoader().hashCode()).append(")")
                            .append("\n");
                    LOG.debug(sb.toString());
                }
                return false;
            } else {
                return true;
            }
        }
    }

    private static class MySignature extends SignatureSpi {
        private final JackNJI11Provider provider;
        private final String algorithm;
        private int opmode;
        private NJI11Object myKey;
        private long session;
        private ByteArrayOutputStream buffer;
        private final int type;
        private AlgorithmParameterSpec params;

        // constant for type digesting, we do the hashing ourselves
        // private final static int T_DIGEST = 1;          // TODO: Currently it is not supported
        
        // constant for type update, token does everything
        private final static int T_UPDATE = 2;
        // constant for type raw, used with NONEwithRSA only
        private final static int T_RAW = 3;
        
        
        public MySignature(Provider provider, String algorithm) {
            super();
            this.provider = (JackNJI11Provider) provider;
            this.algorithm = algorithm;

            if (algorithm.startsWith("NONEwith")) {
                type = T_RAW;
            } else {
                type = T_UPDATE;
            }
        }

        @Override
        protected void engineInitVerify(PublicKey pk) throws InvalidKeyException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected void engineInitSign(PrivateKey pk) throws InvalidKeyException {
            if (pk instanceof NJI11Object == false) {
                throw new InvalidKeyException("Not an NJI11Object: " + pk);
            }
            myKey = (NJI11Object) pk;

            if (pk instanceof NJI11StaticSessionPrivateKey) {
                session = ((NJI11StaticSessionPrivateKey) pk).getSession();
            } else {
                session = myKey.getSlot().aquireSession(); // TODO: If SignInit fails we should release this one
            }
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("enigneInitSign: session: " + session + ", object: " +
                          myKey.getObject());
            }
            
            long sigAlgoValue = MechanismNames.longFromSigAlgoName(this.algorithm);
            byte[] param;
            if (params == null) {
                param = CKM_PARAMS.get(sigAlgoValue);
            } else if (params instanceof PSSParameterSpec) {
                param = encodePssParameters((PSSParameterSpec) params);
            } else {
                throw new InvalidKeyException("Unsupported algorithm parameter: " + params);
            }
            myKey.getSlot().getCryptoki().SignInit(session, new CKM(sigAlgoValue, param), myKey.getObject());
        }

        @Override
        protected void engineUpdate(byte b) throws SignatureException {
            engineUpdate(new byte[]{b}, 0, 1);
        }

        @Override
        protected void engineUpdate(byte[] bytes, int offset, int length) throws SignatureException {
            switch (type) {
                case T_UPDATE:
                    if (offset != 0 || length != bytes.length) {
                        byte[] newArray = Arrays.copyOfRange(bytes, offset, (offset + length));
                        myKey.getSlot().getCryptoki().SignUpdate(session, newArray);
                    } else {
                        myKey.getSlot().getCryptoki().SignUpdate(session, bytes);
                    }
                    break;
                case T_RAW: // No need to call SignUpdte as hash is supplied already
                    buffer = new ByteArrayOutputStream();
                    buffer.write(bytes, offset, length);
                    break;
                default:
                    throw new ProviderException("Internal error");
            }
        }

        @Override
        protected byte[] engineSign() throws SignatureException {
            // TODO: If this fails we should also release the session?
            byte[] result;
            if (type == T_UPDATE) {
                result = myKey.getSlot().getCryptoki().SignFinal(session);
            } else { // single-part operation if hash is provided for signing
                result = myKey.getSlot().getCryptoki().Sign(session, buffer.toByteArray());
            }

            if (myKey instanceof NJI11ReleasebleSessionPrivateKey) {
                myKey.getSlot().releaseSession(session);
            }
            return result;
        }

        @Override
        protected boolean engineVerify(byte[] bytes) throws SignatureException {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @SuppressWarnings({"override", "deprecation"})
        protected void engineSetParameter(String string, Object o) throws InvalidParameterException {
            // Super method is deprecated. Use engineSetParameter(AlgorithmParameterSpec params)
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
            this.params = params;
        }

        @SuppressWarnings({"override", "deprecation"})
        protected Object engineGetParameter(String string) throws InvalidParameterException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        private static byte[] encodePssParameters(final PSSParameterSpec spec) throws InvalidKeyException {
            MGF1ParameterSpec mgfSpec = (MGF1ParameterSpec) spec.getMGFParameters();

            final Long digestMechanism = DIGEST_NAME_TO_CKM_MAP.get(spec.getDigestAlgorithm());
            final Long maskGenMechanism = DIGEST_NAME_TO_CKG_MAP.get(mgfSpec.getDigestAlgorithm());
            final long saltLength = spec.getSaltLength();
            
            if (digestMechanism == null) {
                throw new InvalidKeyException("Unsupported digest in PSS parameters: " + spec.getDigestAlgorithm());
            }

            if (maskGenMechanism == null) {
                throw new InvalidKeyException("Unsupported digest in MGF1 parameters: " + mgfSpec.getDigestAlgorithm());
            }

            return ULong.ulong2b(new long[] {digestMechanism, maskGenMechanism, saltLength});
        }
    }
    
    private static class MyAlgorithmParameters extends PSS {
        // Fall back on BC PSS parameter configuration. 
        @SuppressWarnings("unused")
        public MyAlgorithmParameters(Provider provider, String algorithm) {
            super();
        }
    }
    
    private static class MyMessageDigiest extends MessageDigestSpi {
        // While this MessageDigiest "implementation" doesn't do anything currently, it's required
        // in order for MGF1 Algorithms to work since BC performs a sanity check before
        // creating signatures with PSS parameters. See org.bouncycastle.operator.jcajce.notDefaultPSSParams(...)
        @SuppressWarnings("unused")
        public MyMessageDigiest(Provider provider, String algorithm) {
            super();
        }
        
        @Override
        protected void engineUpdate(byte input) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected void engineUpdate(byte[] input, int offset, int len) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected byte[] engineDigest() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected void engineReset() {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    }
    
}
