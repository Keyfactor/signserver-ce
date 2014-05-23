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

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.ejbca.core.model.ca.catoken.CATokenAuthenticationFailedException;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.catoken.ICAToken;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.signserver.common.*;

/**
 * A base class to wrap around CATokens from EJBCA. Makes it easy to use CA Tokens from EJBCA 
 * as crypto tokens in Signserver.
 * 
 * @see org.signserver.server.cryptotokens.ICryptoToken
 * @author Philip Vendil, Tomas Gustavsson
 * @version $Id$
 */
public abstract class OldCryptoTokenBase implements ICryptoToken {

    private static final Logger log = Logger.getLogger(OldCryptoTokenBase.class);
    protected ICAToken catoken = null;

    /** A workaround for the feature in SignServer 2.0 that property keys are 
     * always converted to upper case. The EJBCA CA Tokens usually use mixed case properties
     */
    protected Properties fixUpProperties(Properties props) {
       return CryptoTokenHelper.fixP11Properties(props);
    }
    
    /**
     * Method returning SignerStatus.STATUS_ACTIVE if every thing is OK, otherwise STATUS_OFFLINE.
     * 
     */
    @Override
    public int getCryptoTokenStatus() {
        int status = catoken.getCATokenStatus();
        if (status == ICAToken.STATUS_ACTIVE) {
            return SignerStatus.STATUS_ACTIVE;
        }
        return SignerStatus.STATUS_OFFLINE;
    }

    /**
     * Method activating the cryptographic token using the given key
     * 
     * @throws CryptoTokenAuthenticationFailureException if activation failed, message gives more info
     * @throws CryptoTokenOfflineException if connection to token could not be created.
     * 
     */
    @Override
    public void activate(String authenticationcode) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException {
        try {
            catoken.activate(authenticationcode);
        } catch (CATokenOfflineException e) {
            throw new CryptoTokenOfflineException(e.getMessage());
        } catch (CATokenAuthenticationFailedException e) {
            throw new CryptoTokenAuthenticationFailureException(e.getMessage());
        }

    }

    /**
     * Method deactivating the cryptographic token
     * 
     * @return true if everything went successful
     */
    @Override
    public boolean deactivate() throws CryptoTokenOfflineException {
        boolean ret = false;
        try {
            ret = catoken.deactivate();
        } catch (Exception e) {
            throw new CryptoTokenOfflineException(e);
        }
        return ret;
    }

    /**
     * Returns a reference to the private key to use.
     * 
     * @see org.signserver.server.cryptotokens.ICryptoToken 
     */
    @Override
    public PrivateKey getPrivateKey(int purpose) throws CryptoTokenOfflineException {
        try {
            return catoken.getPrivateKey(purpose);
        } catch (CATokenOfflineException e) {
            throw new CryptoTokenOfflineException(e.getMessage());
        }
    }

    /**
     * Returns a reference to the public key to use.
     * 
     * @see org.signserver.server.cryptotokens.ICryptoToken 
     */
    @Override
    public PublicKey getPublicKey(int purpose) throws CryptoTokenOfflineException {
        try {
            return catoken.getPublicKey(purpose);
        } catch (CATokenOfflineException e) {
            throw new CryptoTokenOfflineException(e.getMessage());
        }
    }

    /**
     * Returns the provider name that should be used.
     * @see ICryptoToken.PROVIDERUSAGE_SIGN
     */
    @Override
    public String getProvider(int providerUsage) {
        return catoken.getProvider();
    }

    @Override
    public Certificate getCertificate(int purpose) throws CryptoTokenOfflineException {
        return null;
    }

    @Override
    public List<Certificate> getCertificateChain(int purpose) throws CryptoTokenOfflineException {
        return null;
    }

    // TODO: The genCertificateRequest method is mostly a duplicate of the one in CryptoTokenBase, PKCS11CryptoTooken, KeyStoreCryptoToken and SoftCryptoToken.
    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            final boolean explicitEccParameters, final boolean defaultKey)
            throws CryptoTokenOfflineException {
        Base64SignerCertReqData retval = null;
        if (info instanceof PKCS10CertReqInfo) {
            PKCS10CertReqInfo reqInfo = (PKCS10CertReqInfo) info;
            PKCS10CertificationRequest pkcs10;
            final int purpose = defaultKey
                    ? PURPOSE_SIGN : PURPOSE_NEXTKEY;
            if (log.isDebugEnabled()) {
                log.debug("Purpose: " + purpose);
                log.debug("signatureAlgorithm: "
                        + reqInfo.getSignatureAlgorithm());
                log.debug("subjectDN: " + reqInfo.getSubjectDN());
                log.debug("explicitEccParameters: " + explicitEccParameters);
            }

            try {
                PublicKey publicKey = getPublicKey(purpose);

                // Handle ECDSA key with explicit parameters
                if (explicitEccParameters
                        && publicKey.getAlgorithm().contains("EC")) {
                    publicKey = ECKeyUtil.publicToExplicitParameters(publicKey,
                            "BC");
                }
                // Generate request
                final JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(CertTools.stringToBCDNString(reqInfo.getSubjectDN())), publicKey);
                final ContentSigner contentSigner = new JcaContentSignerBuilder(reqInfo.getSignatureAlgorithm()).setProvider(getProvider(ICryptoToken.PROVIDERUSAGE_SIGN)).build(getPrivateKey(purpose));
                pkcs10 = builder.build(contentSigner);
                retval = new Base64SignerCertReqData(Base64.encode(pkcs10.getEncoded()));
            } catch (IOException e) {
                log.error("Certificate request error: " + e.getMessage(), e);
            } catch (OperatorCreationException e) {
                log.error("Certificate request error: signer could not be initialized", e);
            } catch (NoSuchAlgorithmException e) {
                log.error("Certificate request error: " + e.getMessage(), e);
            } catch (NoSuchProviderException e) {
                log.error("Certificate request error: " + e.getMessage(), e);
            }

        }
        return retval;
    }

    /**
     * Method not supported
     */
    @Override
    public boolean destroyKey(int purpose) {
        return false;
    }

    @Override
    public Collection<KeyTestResult> testKey(String alias, char[] authCode)
            throws CryptoTokenOfflineException, KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
