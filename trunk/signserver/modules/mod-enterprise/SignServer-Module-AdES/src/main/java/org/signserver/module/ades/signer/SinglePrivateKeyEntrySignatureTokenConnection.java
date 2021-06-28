/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.ades.signer;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.List;

/**
 * A SignatureTokenConnection that is based on a single PrivateKey a certificate
 * chain and a key alias.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SinglePrivateKeyEntrySignatureTokenConnection extends AbstractSignatureTokenConnection {

    private final List<DSSPrivateKeyEntry> keys;
    
    private final Provider signatureProvider;

    /**
     * Construct an instance from the 3 parts.
     *
     * @param alias key alias
     * @param privateKey the private key reference
     * @param chain the certificate chain
     * @param signatureProvider provider for the signature
     */
    public SinglePrivateKeyEntrySignatureTokenConnection(final String alias, PrivateKey privateKey, List<Certificate> chain, Provider signatureProvider) {
        this(alias, new KeyStore.PrivateKeyEntry(privateKey, chain.toArray(new Certificate[0])), signatureProvider);
    }

    /**
     * Construct an instance using a KeyStore.PrivateKeyEntry and a key alias.
     *
     * @param alias key alias
     * @param entry the private key entry
     * @param signatureProvider provider for the signature
     */
    public SinglePrivateKeyEntrySignatureTokenConnection(final String alias, final KeyStore.PrivateKeyEntry entry, Provider signatureProvider) {
        this.keys = Arrays.asList(new KSPrivateKeyEntry(alias, entry));
        this.signatureProvider = signatureProvider;
    }

    @Override
    public void close() {
        // NOP
    }

    @Override
    public List<DSSPrivateKeyEntry> getKeys() throws DSSException {
        return keys;
    }
    
    @Override
    public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, MaskGenerationFunction mgf,
            DSSPrivateKeyEntry keyEntry) throws DSSException {
        final EncryptionAlgorithm encryptionAlgorithm = keyEntry.getEncryptionAlgorithm();
        final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm,
                digestAlgorithm, mgf);
        String javaSignatureAlgorithm = signatureAlgorithm.getJCEId();

        // XXX: Using RSASSA-PSS instead of withMGF1 due to recent change in Java. This is not expected to work in older Java versions.
        javaSignatureAlgorithm = javaSignatureAlgorithm.replace("andMGF1", "SSA-PSS");

        final byte[] bytes = toBeSigned.getBytes();
        AlgorithmParameterSpec param = null;
        if (mgf != null) {
            param = createPSSParam(digestAlgorithm);
        }

        try {
            final byte[] signatureValue = sign(bytes, javaSignatureAlgorithm, param, keyEntry);
            SignatureValue value = new SignatureValue();
            value.setAlgorithm(signatureAlgorithm);
            value.setValue(signatureValue);
            return value;
        } catch (Exception e) {
            throw new DSSException(e);
        }
    }
    
    private byte[] sign(final byte[] bytes, final String javaSignatureAlgorithm, final AlgorithmParameterSpec param,
			final DSSPrivateKeyEntry keyEntry) throws GeneralSecurityException {
        if (!(keyEntry instanceof KSPrivateKeyEntry)) {
            throw new IllegalArgumentException("Only KSPrivateKeyEntry are supported");
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signature algorithm : {}", javaSignatureAlgorithm);
        }
        final Signature signature = getSignatureInstance(javaSignatureAlgorithm);
        if (param != null) {
            signature.setParameter(param);
        }
        signature.initSign(((KSPrivateKeyEntry) keyEntry).getPrivateKey());
        signature.update(bytes);
        return signature.sign();
    }

    @Override
    protected Signature getSignatureInstance(String javaSignatureAlgorithm) throws NoSuchAlgorithmException {
        return Signature.getInstance(javaSignatureAlgorithm, signatureProvider);
    }
    

}
