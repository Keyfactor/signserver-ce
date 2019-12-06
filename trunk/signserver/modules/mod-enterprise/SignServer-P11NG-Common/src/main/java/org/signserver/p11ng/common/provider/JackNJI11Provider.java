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
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.util.Arrays;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CKM;
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

    @SuppressWarnings("OverridableMethodCallInConstructor")
    public JackNJI11Provider() {
        super(NAME, 0.3, "JackNJI11 Provider");

        putService(new MySigningService(this, "Signature", "NONEwithRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "MD5withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA1withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA224withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA256withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA384withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA512withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "NONEwithDSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA1withDSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA1withRSAandMGF1", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA256withRSAandMGF1", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA384withRSAandMGF1", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA512withRSAandMGF1", MySignature.class.getName()));
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

            if (algorithm.equals("NONEwithRSA")) {
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
            byte[] param = CKM_PARAMS.get(sigAlgoValue);
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
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @SuppressWarnings({"override", "deprecation"})
        protected Object engineGetParameter(String string) throws InvalidParameterException {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    }

}
