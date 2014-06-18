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
package org.signserver.server.cryptotokens;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.List;
import java.util.Properties;
import javax.ejb.EJB;
import javax.naming.NamingException;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.DecoderException;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.common.*;
import org.signserver.ejb.interfaces.IWorkerSession;

/**
 * Cryptographic token that uses soft keys stored in the worker properties in the database.
 * Is support generation of certificate requests and regeneration of keys.
 * Every time genCertificateRequest is called i a new key called. destroyKey method
 * is not supported.
 * 
 * 
 * Currently is only one key supported used for all purposes.
 * 
 * This Cryptographic token should mainly be used for test and demonstration purposes
 * not for production.
 * 
 * Available properties are:
 * KEYALG : The algorithms of the keys generated. (for future use, currently is only "RSA" supported and the one used by default).
 * KEYSPEC : The specification of the keys generated. (Optional). If not set will "2048" be used.
 * KEYDATA : The base64 encoded key data.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class SoftCryptoToken implements ICryptoToken {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SoftCryptoToken.class);
	
    public static final String PROPERTY_KEYDATA = "KEYDATA";
    public static final String PROPERTY_KEYALG = "KEYALG";
    public static final String PROPERTY_KEYSPEC = "KEYSPEC";
	
    private int workerId;
    private KeyPair keys = null;
    private String keySpec = null;
    private String keyAlg = null;
    private boolean active = true;
    
    // FIXME:  Consider doing manual injection using the init method or similar. If it really needs to use the worker session?
    private IWorkerSession workerSession;

    /**
     * @see org.signserver.server.cryptotokens.ICryptoToken#init(int, java.util.Properties)
     */
    @Override
    public void init(int workerId, Properties props) {
        this.workerId = workerId;
        keySpec = props.getProperty(PROPERTY_KEYSPEC, "2048");
        keyAlg = props.getProperty(PROPERTY_KEYALG, "RSA");
        final String keyDataValue = props.getProperty(PROPERTY_KEYDATA);

        if (keyDataValue != null) {
            try {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                byte[] keyData = Base64.decode(keyDataValue.getBytes());
                ByteArrayInputStream bais = new ByteArrayInputStream(keyData);
                DataInputStream dis = new DataInputStream(bais);

                int pubKeySize = dis.readInt();
                byte[] pubKeyData = new byte[pubKeySize];
                dis.read(pubKeyData, 0, pubKeySize);
                int privKeySize = dis.readInt();
                byte[] privKeyData = new byte[privKeySize];
                dis.read(privKeyData, 0, privKeySize);
                // decode public key
                X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyData);
                RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(pubSpec);

                // decode private key
                PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyData);
                RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);

                keys = new KeyPair(pubKey, privKey);
            } catch (NoSuchAlgorithmException e) {
                LOG.error("Error loading soft keys : KEYDATA=\"" + keyDataValue + "\"", e);
            } catch (IOException e) {
                LOG.error("Error loading soft keys : KEYDATA=\"" + keyDataValue + "\"", e);
            } catch (InvalidKeySpecException e) {
                LOG.error("Error loading soft keys : KEYDATA=\"" + keyDataValue + "\"", e);
            } catch (DecoderException e) {
                LOG.error("Error loading soft keys : KEYDATA=\"" + keyDataValue + "\"", e);
            }
        } else {
            active = false;
        }

    }

    /**
     * Returns true if the key store was properly loaded
     * 
     * @see org.signserver.server.cryptotokens.ICryptoToken#getCryptoTokenStatus()
     * 
     */
    @Override
    public int getCryptoTokenStatus() {
        if (active) {
            return WorkerStatus.STATUS_ACTIVE;
        }
        return WorkerStatus.STATUS_OFFLINE;
    }

    /**
     * Loads the key store into memory
     * 
     * @see org.signserver.server.cryptotokens.ICryptoToken#activate(java.lang.String)
     */
    @Override
    public void activate(String authenticationcode)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException {
        active = keys != null;
    }

    /**
     * Method that clear the key data from memory.
     * 
     * @see org.signserver.server.cryptotokens.ICryptoToken#deactivate()
     */
    @Override
    public boolean deactivate() {
        active = false;
        return true;
    }

    /**
     * Returns the same private key for all purposes.
     * @see org.signserver.server.cryptotokens.ICryptoToken#getPrivateKey(int)
     */
    @Override
    public PrivateKey getPrivateKey(int purpose)
            throws CryptoTokenOfflineException {

        if (!active) {
            throw new CryptoTokenOfflineException("Signtoken isn't active.");
        }
        return keys.getPrivate();
    }

    /**
     * Returns the same public key for all purposes.
     * @see org.signserver.server.cryptotokens.ICryptoToken#getPublicKey(int)
     */
    @Override
    public PublicKey getPublicKey(int purpose) throws CryptoTokenOfflineException {

        if (!active) {
            throw new CryptoTokenOfflineException("Signtoken isn't active.");
        }
        return keys.getPublic();
    }

    /**
     * Always returns BC.
     * @see org.signserver.server.cryptotokens.ICryptoToken#getPrivateKey(int)
     */
    @Override
    public String getProvider(int providerUsage) {
        return "BC";
    }

    @Override
    public Certificate getCertificate(int purpose) throws CryptoTokenOfflineException {
        return null;
    }

    @Override
    public List<Certificate> getCertificateChain(int purpose) throws CryptoTokenOfflineException {
        return null;
    }

    /**
     * Special method that generates a new key pair that is written to the worker configuration
     * before the request is generated. The new keys aren't activated until reload is issued.
     * 
     */
    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            final boolean explicitEccParameters, final boolean defaultKey)
            throws CryptoTokenOfflineException {
        Base64SignerCertReqData retval = null;

        try {
            KeyPair newKeys = KeyTools.genKeys(keySpec, keyAlg);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            byte[] pubKeyData = newKeys.getPublic().getEncoded();
            byte[] prvKeyData = newKeys.getPrivate().getEncoded();
            dos.writeInt(pubKeyData.length);
            dos.write(pubKeyData);
            dos.writeInt(prvKeyData.length);
            dos.write(prvKeyData);

            getWorkerSession().setWorkerProperty(workerId, PROPERTY_KEYDATA, new String(Base64.encode(baos.toByteArray())));

            if (info instanceof PKCS10CertReqInfo) {
                PKCS10CertReqInfo reqInfo = (PKCS10CertReqInfo) info;
                PKCS10CertificationRequest pkcs10;
                PublicKey publicKey = newKeys.getPublic();

                // Handle ECDSA key with explicit parameters
                if (explicitEccParameters
                        && publicKey.getAlgorithm().contains("EC")) {
                    publicKey = ECKeyUtil.publicToExplicitParameters(publicKey,
                            "BC");
                }
                // Generate request
                // Generate request
                final JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(CertTools.stringToBCDNString(reqInfo.getSubjectDN())), publicKey);
                final ContentSigner contentSigner = new JcaContentSignerBuilder(reqInfo.getSignatureAlgorithm()).setProvider(getProvider(ICryptoToken.PROVIDERUSAGE_SIGN)).build(newKeys.getPrivate());
                pkcs10 = builder.build(contentSigner);
                retval = new Base64SignerCertReqData(Base64.encode(pkcs10.getEncoded()));
            }
        } catch (IOException e) {
            LOG.error("Certificate request error: " + e.getMessage(), e);
        } catch (OperatorCreationException e) {
            LOG.error("Certificate request error: signer could not be initialized", e);
        } catch (NoSuchAlgorithmException e1) {
            LOG.error("Error generating new certificate request : " + e1.getMessage(), e1);
        } catch (NoSuchProviderException e1) {
            LOG.error("Error generating new certificate request : " + e1.getMessage(), e1);
        } catch (InvalidAlgorithmParameterException e1) {
            LOG.error("Error generating new certificate request : " + e1.getMessage(), e1);
        } catch (NamingException e1) {
            LOG.error("Error generating new certificate request : " + e1.getMessage(), e1);
        }
        return retval;
    }

    /**
     * Method not supported
     */
    @Override
    public boolean destroyKey(int purpose) {
        LOG.error("destroyKey method isn't supported");
        return false;
    }

    protected IWorkerSession getWorkerSession() throws NamingException {
        if (workerSession == null) {
            workerSession = ServiceLocator.getInstance().lookupLocal(
                    IWorkerSession.class);
        }
        return workerSession;
    }

    @Override
    public Collection<KeyTestResult> testKey(final String alias,
            final char[] authCode) throws CryptoTokenOfflineException,
            KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public KeyStore getKeyStore() throws UnsupportedOperationException,
            CryptoTokenOfflineException, KeyStoreException {
        throw new UnsupportedOperationException(
                "Operation not supported by crypto token.");
    }
}
