/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.server.cryptotokens;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.operator.OperatorCreationException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.DuplicateAliasException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.NoSuchAliasException;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.TokenOutOfSpaceException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.server.IServices;

import static org.signserver.server.cesecore.certificates.util.AlgorithmTools.getKeySpecification;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_ALGORITHM;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.createKeyHash;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.testSignAndVerify;

/**
 * Helper methods for composite related logic.
 * Future: Parts may be refactoried out to KFC/x509-common-util.
 */
public class CompositeHelper {
    
    private static final Logger LOG = Logger.getLogger(CompositeHelper.class);

    /** Suffix for first component , the PQC one. */
    public static final String KEYALIAS_COMPQ_SUFFIX = "-COMPQ";

    /** Suffix for second component , the classical one. */
    public static final String KEYALIAS_COMPC_SUFFIX = "-COMPC";

    /** Suffix for the virtual composite key. */
    public static final String KEYALIAS_COMPOSITE_SUFFIX = "-COMPOSITE";

    private ICryptoTokenV4 delegate;

    private final String keyAliasSuffix;

    public CompositeHelper(String keyAliasSuffix) {
        this.keyAliasSuffix = keyAliasSuffix;
    }
    
    public CompositeHelper(ICryptoTokenV4 delegate) {
        this.delegate = delegate;
        this.keyAliasSuffix = "";
    }
    
    public ICryptoTokenV4 getDelegate(IServices services) throws CryptoTokenOfflineException {
        if (delegate == null) {
            throw new IllegalStateException("CompositeHelper without delegate");
        }
        return delegate;
    }

    public Optional<ICertReqData> genCertificateRequest(final ISignerCertReqInfo info,
                                                  final boolean explicitEccParameters,
                                                  final String alias,
                                                  final IServices services)
                throws CryptoTokenOfflineException {

        if (alias == null || (!KEYALIAS_COMPOSITE_SUFFIX.equals(keyAliasSuffix) && !alias.endsWith(KEYALIAS_COMPOSITE_SUFFIX))) {
            LOG.info("Key alias not for composite: " + alias);
            return Optional.empty();
        }

        if (info instanceof PKCS10CertReqInfo certReqInfo) {
            final ICryptoTokenV4 token = getDelegate(services);

            RequestContext context = new RequestContext(true);
            context.setServices(services);

            ICryptoInstance crypto1 = null;
            ICryptoInstance crypto2 = null;
            try {
                final String aliasComp1 = removeCompositeSuffix(alias) + KEYALIAS_COMPQ_SUFFIX;
                crypto1 = token.acquireCryptoInstance(aliasComp1, Collections.emptyMap(), context);
                final String algComp1 = crypto1.getPublicKey().getAlgorithm();

                final String aliasComp2 = removeCompositeSuffix(alias) + KEYALIAS_COMPC_SUFFIX;
                crypto2 = token.acquireCryptoInstance(aliasComp2, Collections.emptyMap(), context);
                final String algComp2 = crypto2.getPublicKey().getAlgorithm();

                if (!algComp1.startsWith("ML-DSA")) {
                    throw new CryptoTokenOfflineException("Unexpected PQC algorithm for composite: " + crypto1.getPublicKey().getAlgorithm());
                }

                if (!"RSA".equalsIgnoreCase(algComp2) && !"EC".equalsIgnoreCase(algComp2) && !"Ed25519".equalsIgnoreCase(algComp2) && !"Ed448".equalsIgnoreCase(algComp2)) {
                    throw new CryptoTokenOfflineException("Unexpected classic algorithm for composite: " + crypto2.getPublicKey().getAlgorithm());
                }

                // Get OID for composites with ECDSA brainpool (To be removed with BC 1.84 upgrade)
                if ("EC".equalsIgnoreCase(algComp2) && certReqInfo.getSignatureAlgorithm().contains("brainpool")) {
                    String signatureAlgorithm = certReqInfo.getSignatureAlgorithm();
                    ASN1ObjectIdentifier algOid;
                    if (signatureAlgorithm.equalsIgnoreCase("MLDSA65-ECDSA-brainpoolP256r1-SHA512")) {
                        algOid = IANAObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512;
                    } else if (signatureAlgorithm.equalsIgnoreCase("MLDSA87-ECDSA-brainpoolP384r1-SHA512")) {
                        algOid = IANAObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512;
                    } else {
                        throw new IllegalArgumentException("Unexpected classic algorithm for composite: " + algComp2);
                    }

                    return compositeBuilder(certReqInfo, algOid, crypto1, crypto2, explicitEccParameters);

                    // Get OID for omposites with EdDSA (To be removed with BC 1.84 upgrade)
                } else if ("Ed25519".equalsIgnoreCase(algComp2) || "Ed448".equalsIgnoreCase(algComp2)) {
                    String signatureAlgorithm = certReqInfo.getSignatureAlgorithm();
                    ASN1ObjectIdentifier algOid;
                    if (signatureAlgorithm.equalsIgnoreCase("MLDSA44-Ed25519-SHA512")) {
                        algOid = IANAObjectIdentifiers.id_MLDSA44_Ed25519_SHA512;
                    } else if (signatureAlgorithm.equalsIgnoreCase("MLDSA65-Ed25519-SHA512")) {
                        algOid = IANAObjectIdentifiers.id_MLDSA65_Ed25519_SHA512;
                    } else if (signatureAlgorithm.equalsIgnoreCase("MLDSA87-Ed448-SHAKE256")) {
                        algOid = IANAObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256;
                    } else {
                        throw new IllegalArgumentException("Unexpected classic algorithm for composite: " + algComp2);
                    }

                    return compositeBuilder(certReqInfo, algOid, crypto1, crypto2, explicitEccParameters);

                }

                CompositePublicKey compPublicKey = CompositePublicKey.builder(certReqInfo.getSignatureAlgorithm())
                .addPublicKey(crypto1.getPublicKey(), "BC")
                .addPublicKey(crypto2.getPublicKey(), "BC")
                .build();
                CompositePrivateKey compPrivateKey = CompositePrivateKey.builder(certReqInfo.getSignatureAlgorithm())
                .addPrivateKey(crypto1.getPrivateKey(), crypto1.getProvider())
                .addPrivateKey(crypto2.getPrivateKey(), crypto2.getProvider())
                .build();

                return Optional.of(CryptoTokenHelper.genCertificateRequest(certReqInfo, compPrivateKey, "BC", compPublicKey, explicitEccParameters));
            } catch (InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter | IllegalRequestException | SignServerException ex) {
                throw new CryptoTokenOfflineException(ex);
            } catch (NoSuchAliasException ex) {
                LOG.error("Composite component key not existing: " + ex.getMessage());
                throw new CryptoTokenOfflineException("Composite component key not existing: " + ex.getMessage(), ex);
            } finally {
                if (crypto1 != null) {
                    token.releaseCryptoInstance(crypto1, context);
                }
                if (crypto2 != null) {
                    token.releaseCryptoInstance(crypto2, context);
                }
            }
        } else {
            throw new IllegalArgumentException("Unsupported certificate request info type: " + info);
        }
    }

    /**
     * Method that creates a CSR for composites that are not mapped in Bouncy Castle 1.83.
     * Should be removed when BC is upgraded and this is no longer needed.
     * @param certReqInfo
     * @param algorithmOid
     * @param crypto1
     * @param crypto2
     * @param explicitEccParameters
     * @return certificate request data
     */
    private Optional<ICertReqData> compositeBuilder(PKCS10CertReqInfo certReqInfo, ASN1ObjectIdentifier algorithmOid, ICryptoInstance crypto1, ICryptoInstance crypto2, boolean explicitEccParameters) {
        CompositePublicKey compositePublicKey = CompositePublicKey.builder(algorithmOid)
                .addPublicKey(crypto1.getPublicKey(), "BC")
                .addPublicKey(crypto2.getPublicKey(), "BC").build();
        CompositePrivateKey compositePrivateKey = CompositePrivateKey.builder(algorithmOid)
                .addPrivateKey(crypto1.getPrivateKey(), crypto1.getProvider())
                .addPrivateKey(crypto2.getPrivateKey(), crypto2.getProvider())
                .build();

        return Optional.ofNullable(CryptoTokenHelper.genCertificateRequest(certReqInfo, compositePrivateKey, "BC", compositePublicKey, explicitEccParameters));
    }
    public Optional<ICryptoInstance> acquireCryptoInstance(final String alias,
                                                     final Map<String, Object> params,
                                                     final RequestContext context) throws
                CryptoTokenOfflineException,
                NoSuchAliasException,
                InvalidAlgorithmParameterException,
                UnsupportedCryptoTokenParameter,
                IllegalRequestException,
                SignServerException {

            if (alias == null || (!KEYALIAS_COMPOSITE_SUFFIX.equals(keyAliasSuffix) && !alias.endsWith(KEYALIAS_COMPOSITE_SUFFIX)) || alias.endsWith(KEYALIAS_COMPQ_SUFFIX) || alias.endsWith(KEYALIAS_COMPC_SUFFIX)) {
                LOG.info("Key alias not for composite: " + alias);
                return Optional.empty();
            }
            final ICryptoTokenV4 token = getDelegate(context.getServices());
            ICryptoInstance crypto1 = null;
            ICryptoInstance crypto2 = null;
            boolean success = false;

            try {
                final String aliasComp1 = removeCompositeSuffix(alias) + KEYALIAS_COMPQ_SUFFIX;
                crypto1 = token.acquireCryptoInstance(aliasComp1, params, context);
                final String algComp1 = crypto1.getPublicKey().getAlgorithm();

                final String aliasComp2 = removeCompositeSuffix(alias) + KEYALIAS_COMPC_SUFFIX;
                crypto2 = token.acquireCryptoInstance(aliasComp2, params, context);
                final String algComp2 = crypto2.getPublicKey().getAlgorithm();

                if (!algComp1.startsWith("ML-DSA")) {
                    throw new CryptoTokenOfflineException("Unexpected PQC algorithm for composite: " + crypto1.getPublicKey().getAlgorithm());
                }
                
                if (!"RSA".equalsIgnoreCase(algComp2) && !"EC".equalsIgnoreCase(algComp2) && !"Ed25519".equalsIgnoreCase(algComp2) && !"Ed448".equalsIgnoreCase(algComp2)) {
                    throw new CryptoTokenOfflineException("Unexpected classic algorithm for composite: " + crypto2.getPublicKey().getAlgorithm());
                }
                
                String signatureAlgorithm = (String) params.get(ICryptoTokenV4.PARAM_SIGNATURE_ALGORITHM);
                X509Certificate signerCertificate = (X509Certificate) params.get(ICryptoTokenV4.PARAM_SIGNER_CERTIFICATE);
                Boolean useDefaultSignatureAlgorithm = (Boolean) params.get(ICryptoTokenV4.PARAM_USE_DEFAULT_SIGNATURE_ALGORITHM);

                if (signerCertificate != null) {
                    String publicKeyAlgorithm = signerCertificate.getPublicKey().getAlgorithm();

                    if (signatureAlgorithm != null) {
                        if (!signatureAlgorithm.equalsIgnoreCase(publicKeyAlgorithm)) {
                            throw new CryptoTokenOfflineException("Different signature algorithm and certificate public key algorithm: \"" + signatureAlgorithm + "\" vs. \"" + publicKeyAlgorithm + "\"");
                        }
                    } else {
                        signatureAlgorithm = publicKeyAlgorithm;
                    }
                }
                final CompositePublicKey.Builder pubBuilder;
                final CompositePrivateKey.Builder privBuilder;
                if (useDefaultSignatureAlgorithm != null && useDefaultSignatureAlgorithm) {
                    String classicalSpec = getKeySpecification(crypto2.getPublicKey());
                    ASN1ObjectIdentifier compositeOID = CompositeHelper.getDefaultCompositeAlgorithm(algComp1, classicalSpec, algComp2).orElseThrow(); // TODO throw
                    pubBuilder = CompositePublicKey.builder(compositeOID);
                    privBuilder = CompositePrivateKey.builder(compositeOID);
                } else {
                    if (signatureAlgorithm == null) {
                        throw new CryptoTokenOfflineException("Must specify SIGNATUREALGORITHM or upload signer certificate to worker, for composites to work");
                    }
                    pubBuilder = CompositePublicKey.builder(signatureAlgorithm);
                    privBuilder = CompositePrivateKey.builder(signatureAlgorithm);
                }
                CompositePublicKey compPublicKey = pubBuilder
                    .addPublicKey(crypto1.getPublicKey(), "BC")
                    .addPublicKey(crypto2.getPublicKey(), "BC")
                    .build();
                CompositePrivateKey compPrivateKey = privBuilder
                    .addPrivateKey(crypto1.getPrivateKey(), crypto1.getProvider())
                    .addPrivateKey(crypto2.getPrivateKey(), crypto2.getProvider())
                    .build();
                final Optional<ICryptoInstance> result = Optional.of(new CompositeCryptoInstance(crypto1, crypto2, alias, context, Security.getProvider("BC"), compPrivateKey, compPublicKey));
                success = true;
                return result;

            } catch (IllegalArgumentException ex) {
                throw new CryptoTokenOfflineException("Can not construct composite: " + ex.getMessage());
            } catch (InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter | IllegalRequestException | SignServerException ex) {
                throw new CryptoTokenOfflineException(ex);
            } finally {
                if (!success) {
                    if (crypto1 != null) {
                        releaseCryptoInstance(crypto1, context);
                    }
                    if (crypto2 != null) {
                        releaseCryptoInstance(crypto2, context);
                    }
                }
            }
        }

        public boolean releaseCryptoInstance(final ICryptoInstance instance,
                                          final RequestContext context) {
            if (instance instanceof CompositeCryptoInstance compInstance) {
                try {
                    final ICryptoTokenV4 token = getDelegate(context.getServices());
                    
                    if (compInstance.getSourceInstance1() != null) {
                        token.releaseCryptoInstance(compInstance.getSourceInstance1(), context);
                    }
                    
                    if (compInstance.getSourceInstance2() != null) {
                        token.releaseCryptoInstance(compInstance.getSourceInstance2(), context);
                    }
                    
                    // Unregister the instance
                    CryptoInstances.getInstance(context).remove(instance);
                } catch (CryptoTokenOfflineException ex) {
                    LOG.warn("Failed to get crypto token to release crypto instance");
                }
                return true;
            } else {
                return false;
            }
        }

    public boolean generateKey(final String keyAlgorithm,
                            final String keySpec,
                            final String alias, final char[] authCode,
                            final Map<String, Object> params,
                            final IServices services)
            throws TokenOutOfSpaceException, CryptoTokenOfflineException,
                   DuplicateAliasException, NoSuchAlgorithmException,
                   InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {

        if (alias == null || (!KEYALIAS_COMPOSITE_SUFFIX.equals(keyAliasSuffix) && !alias.endsWith(KEYALIAS_COMPOSITE_SUFFIX)) || alias.endsWith(KEYALIAS_COMPQ_SUFFIX) || alias.endsWith(KEYALIAS_COMPC_SUFFIX)) {
            LOG.info("Key alias not for composite: " + alias);
            return false;
        }
        final ICryptoTokenV4 token = getDelegate(services);

        final String aliasComp1 = removeCompositeSuffix(alias) + KEYALIAS_COMPQ_SUFFIX;
        final String keyAlgorithm1;
        final String keySpec1;

        final String aliasComp2 = removeCompositeSuffix(alias) + KEYALIAS_COMPC_SUFFIX;
        final String keyAlgorithm2;
        final String keySpec2;

        if (keyAlgorithm == null || (!"COMPOSITE".equalsIgnoreCase(keyAlgorithm) && !keyAlgorithm.equals(keySpec))) {
            throw new NoSuchAlgorithmException("Key algorithm not supported by " + getClass().getSimpleName() + ": " + keyAlgorithm);
        }

        switch (keySpec) {
            case "MLDSA44-RSA2048-PSS-SHA256": {
                keyAlgorithm1 = "ML-DSA";
                keySpec1 = "ML-DSA-44";
                keyAlgorithm2 = "RSA";
                keySpec2 = "2048";
                break;
            }
            case "MLDSA65-RSA3072-PSS-SHA512": {
                keyAlgorithm1 = "ML-DSA";
                keySpec1 = "ML-DSA-65";
                keyAlgorithm2 = "RSA";
                keySpec2 = "3072";
                break;
            }
            case "MLDSA65-RSA4096-PSS-SHA512": {
                keyAlgorithm1 = "ML-DSA";
                keySpec1 = "ML-DSA-65";
                keyAlgorithm2 = "RSA";
                keySpec2 = "4096";
                break;
            }
            case "MLDSA87-RSA3072-PSS-SHA512": {
                keyAlgorithm1 = "ML-DSA";
                keySpec1 = "ML-DSA-87";
                keyAlgorithm2 = "RSA";
                keySpec2 = "3072";
                break;
            }
            case "MLDSA87-RSA4096-PSS-SHA512": {
                keyAlgorithm1 = "ML-DSA";
                keySpec1 = "ML-DSA-87";
                keyAlgorithm2 = "RSA";
                keySpec2 = "4096";
                break;
            }
            case "MLDSA44-ECDSA-P256-SHA256": {
                keyAlgorithm1 = "ML-DSA";
                keySpec1 = "ML-DSA-44";
                keyAlgorithm2 = "ECDSA";
                keySpec2 = "P-256";
                break;
            }
            case "MLDSA65-ECDSA-P256-SHA512": {
                keyAlgorithm1 = "ML-DSA";
                keySpec1 = "ML-DSA-65";
                keyAlgorithm2 = "ECDSA";
                keySpec2 = "P-256";
                break;
            }
            case "MLDSA65-ECDSA-P384-SHA512": {
                keyAlgorithm1 = "ML-DSA";
                keySpec1 = "ML-DSA-65";
                keyAlgorithm2 = "ECDSA";
                keySpec2 = "P-384";
                break;
            }
            case "MLDSA87-ECDSA-P384-SHA512": {
                keyAlgorithm1 = "ML-DSA";
                keySpec1 = "ML-DSA-87";
                keyAlgorithm2 = "ECDSA";
                keySpec2 = "P-384";
                break;
            }
            case "MLDSA87-ECDSA-P521-SHA512": {
                keyAlgorithm1 = "ML-DSA";
                keySpec1 = "ML-DSA-87";
                keyAlgorithm2 = "ECDSA";
                keySpec2 = "P-521";
                break;
            }
            case "MLDSA44-ED25519-SHA512": {
                keyAlgorithm1 = "ML-DSA";
                keySpec1 = "ML-DSA-44";
                keyAlgorithm2 = "EdDSA";
                keySpec2 = "Ed25519";
                break;
            }
            case "MLDSA65-ED25519-SHA512": {
                keyAlgorithm1 = "ML-DSA";
                keySpec1 = "ML-DSA-65";
                keyAlgorithm2 = "EdDSA";
                keySpec2 = "Ed25519";
                break;
            }
            case "MLDSA65-ECDSA-brainpoolP256r1-SHA512": {
                keyAlgorithm1 = "ML-DSA";
                keySpec1 = "ML-DSA-65";
                keyAlgorithm2 = "ECDSA";
                keySpec2 = "brainpoolP256r1";
                break;
            }
            case "MLDSA87-ECDSA-brainpoolP384r1-SHA512": {
                keyAlgorithm1 = "ML-DSA";
                keySpec1 = "ML-DSA-87";
                keyAlgorithm2 = "ECDSA";
                keySpec2 = "brainpoolP384r1";
                break;
            }
            case "MLDSA87-Ed448-SHAKE256": {
                keyAlgorithm1 = "ML-DSA";
                keySpec1 = "ML-DSA-87";
                keyAlgorithm2 = "EdDSA";
                keySpec2 = "Ed448";
                break;
            }
            default:
                throw new NoSuchAlgorithmException("Not supported by " + getClass().getSimpleName() + ": " + keyAlgorithm);
        }

        token.generateKey(keyAlgorithm1, keySpec1, aliasComp1, authCode, params, services);
        token.generateKey(keyAlgorithm2, keySpec2, aliasComp2, authCode, params, services);
        return true;
    }

    /**
     * Suggest a working default composite algorithm to use given the provided PQC and classical
     * algorithms used.
     * @param specPQC Key specification for the PQC component
     * @param specClassical Key specification for the classical component
     * @param typeClassical Key type for the classical component
     * @return OID for the suggested composite algorithm
     */
    public static Optional<ASN1ObjectIdentifier> getDefaultCompositeAlgorithm(String specPQC, String specClassical, String typeClassical) {
        ASN1ObjectIdentifier compositeOID = null;
        if ("RSA".equalsIgnoreCase(typeClassical)) {
            if (specPQC.equalsIgnoreCase("ML-DSA-44")) {
                compositeOID = IANAObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256;
            } else if (specPQC.equalsIgnoreCase("ML-DSA-65")) {
                if (specClassical.equalsIgnoreCase("3072")) {
                    compositeOID = IANAObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512;
                } else {
                    compositeOID = IANAObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA512;
                }
            } else if (specPQC.equalsIgnoreCase("ML-DSA-87")) {
                if (specClassical.equalsIgnoreCase("3072")) {
                    compositeOID = IANAObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512;
                } else {
                    compositeOID = IANAObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512;
                }
            }
        } else if ("EC".equalsIgnoreCase(typeClassical)) {
            if (specPQC.equalsIgnoreCase("ML-DSA-44")) {
                compositeOID = IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256;
            }  else if (specPQC.equalsIgnoreCase("ML-DSA-65")) {
                if (specClassical.equalsIgnoreCase("prime256v1")) {
                    compositeOID = IANAObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512;
                } else {
                    compositeOID = IANAObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512;
                }
            } else if (specPQC.equalsIgnoreCase("ML-DSA-87")) {
                if (specClassical.equalsIgnoreCase("secp384r1")) {
                    compositeOID = IANAObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512;
                } else {
                    compositeOID = IANAObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512;
                }
            }
        }
        return Optional.ofNullable(compositeOID);
    }

    public List<TokenEntry> addCompositeEntries(List<TokenEntry> entries, boolean includeData) {
        return addOrFilterCompositeEntries(entries, entries, includeData);
    }

    public List<TokenEntry> addOrFilterCompositeEntries(List<TokenEntry> allEntries, List<TokenEntry> initialEntries, boolean includeData) {
        List<TokenEntry> result = new ArrayList<>(initialEntries);

        Map<String, CompositeEntry> composites = new HashMap<>();

        allEntries.stream()
            .filter(t -> /*(keyAliasSuffix.isEmpty() || t.getAlias().endsWith(keyAliasSuffix))
                    && */(t.getAlias().endsWith(KEYALIAS_COMPQ_SUFFIX) || t.getAlias().endsWith(KEYALIAS_COMPC_SUFFIX)))
            .forEach(t -> {
                String alias = removeSuffix(removeSuffix(t.getAlias()) + (keyAliasSuffix != KEYALIAS_COMPOSITE_SUFFIX ? KEYALIAS_COMPOSITE_SUFFIX : ""));

                CompositeEntry composite = composites.get(alias);
                if (composite == null) {
                    composite = new CompositeEntry();
                    composites.put(alias, composite);
                }

                if (t.getAlias().endsWith(KEYALIAS_COMPQ_SUFFIX)) {
                    composite.comp1 = t;
                } else if (t.getAlias().endsWith(KEYALIAS_COMPC_SUFFIX)) {
                    composite.comp2 = t;
                }

                if (composite.comp1 != null && composite.comp2 != null) {
                    TokenEntry entry = new TokenEntry(alias, TokenEntry.TYPE_PRIVATEKEY_ENTRY);

                    if (includeData) {
                        final Map<String, String> info = new HashMap<>();

                        info.put(INFO_KEY_ALGORITHM, "COMPOSITE");

                        entry.setInfo(info);
                        try {
                            entry.setParsedChain(new Certificate[0]);
                        } catch (CertificateEncodingException ex) {
                            LOG.warn("Unable to parse certificate for entry " + alias + ": " + ex.getMessage());
                        }
                    }

                    result.add(entry);
                }

            });
        return result;
    }

    private String removeCompositeSuffix(String alias) {
        if (alias.endsWith(KEYALIAS_COMPOSITE_SUFFIX)) {
            alias = alias.substring(0, alias.length() - KEYALIAS_COMPOSITE_SUFFIX.length());
        }
        return alias;
    }

    private String removeSuffix(String alias) {
        String result = alias;
        if (result.endsWith(keyAliasSuffix)) {
            result = result.substring(0, result.length() - keyAliasSuffix.length());
        }
        if (result.endsWith(KEYALIAS_COMPQ_SUFFIX)) {
            result = result.substring(0, result.length() - KEYALIAS_COMPQ_SUFFIX.length());
        } else if (result.endsWith(KEYALIAS_COMPC_SUFFIX)) {
            result = result.substring(0, result.length() - KEYALIAS_COMPC_SUFFIX.length());
        }
        return result;
    }

    public boolean isCompositeAlias(String alias) {
        return alias.endsWith(KEYALIAS_COMPOSITE_SUFFIX) && !alias.endsWith(KEYALIAS_COMPQ_SUFFIX) && !alias.endsWith(KEYALIAS_COMPC_SUFFIX); // TODO support for composite crypto worker also
    }

    public KeyTestResult testKey(KeyStoreDelegator keyStore, String alias, char[] authCode, String signatureProvider, String signatureAlgorithm) throws CryptoTokenOfflineException, KeyStoreException {

        PrivateKey privateKey1 = null;
        PrivateKey privateKey2 = null;
        try {
            final String aliasComp1 = removeCompositeSuffix(alias) + KEYALIAS_COMPQ_SUFFIX;
            privateKey1 = keyStore.aquirePrivateKey(aliasComp1, authCode);
            final PublicKey publicKey1 = keyStore.getPublicKey(aliasComp1);
            final String algComp1 = publicKey1.getAlgorithm();

            final String aliasComp2 = removeCompositeSuffix(alias) + KEYALIAS_COMPC_SUFFIX;
            privateKey2 = keyStore.aquirePrivateKey(aliasComp2, authCode);
            final PublicKey publicKey2 = keyStore.getPublicKey(aliasComp2);
            final String algComp2 = publicKey2.getAlgorithm();

            if (!algComp1.startsWith("ML-DSA")) {
                throw new CryptoTokenOfflineException("Unexpected PQC algorithm for composite: " + algComp1);
            }

            if (!"RSA".equalsIgnoreCase(algComp2) && !"EC".equalsIgnoreCase(algComp2) && !"Ed25519".equalsIgnoreCase(algComp2) && !"Ed448".equalsIgnoreCase(algComp2)) {
                throw new CryptoTokenOfflineException("Unexpected classic algorithm for composite: " + algComp2);
            }

            String classicalSpec = getKeySpecification(publicKey2);
            ASN1ObjectIdentifier compositeOID = CompositeHelper.getDefaultCompositeAlgorithm(algComp1, classicalSpec, algComp2).orElseThrow(() -> new CryptoTokenOfflineException("No default composite algorithm found"));

            CompositePublicKey compPublicKey = CompositePublicKey.builder(compositeOID)
            .addPublicKey(publicKey1, "BC")
            .addPublicKey(publicKey2, "BC")
            .build();
            CompositePrivateKey compPrivateKey = CompositePrivateKey.builder(compositeOID)
            .addPrivateKey(privateKey1, signatureProvider)
            .addPrivateKey(privateKey2, signatureProvider)
            .build();

            return CompositeHelper.testPrivateKey(compPrivateKey, compPublicKey, alias, "BC", compPublicKey.getAlgorithm());
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
            throw new CryptoTokenOfflineException(ex);
        } finally {
            if (privateKey1 != null) {
                keyStore.releasePrivateKey(privateKey1);
            }
            if (privateKey2 != null) {
                keyStore.releasePrivateKey(privateKey2);
            }
        }
    }
    
    public static KeyTestResult testPrivateKey(PrivateKey privateKey, final PublicKey publicKey, String keyAlias, String signatureProvider, String signatureAlgorithm) throws CryptoTokenOfflineException {
        boolean success = false;
        String publicKeyHash = null;
        String status;
        try {
            if (publicKey != null) {
                publicKeyHash = createKeyHash(publicKey);
                testSignAndVerify(privateKey, publicKey, signatureProvider, signatureAlgorithm);
                success = true;
                status = "";
            } else {
                status = "Not testing keys with alias "
                        + keyAlias + ". No public key exists.";
            }
        } catch (ClassCastException ce) {
            status = "Not testing keys with alias "
                    + keyAlias + ". Not a private key.";
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | OperatorCreationException | IOException ex) {
            LOG.error("Error testing key: " + keyAlias, ex);
            status = ex.getMessage();
        }

        return new KeyTestResult(keyAlias, success, status, publicKeyHash);
    }

    /** Holder for a Composite Entry. */
    private static final class CompositeEntry {
        private TokenEntry comp1;
        private TokenEntry comp2;
    }

    private static class CompositeCryptoInstance extends DefaultCryptoInstance {

        private final ICryptoInstance sourceInstance1;
        private final ICryptoInstance sourceInstance2;

        public CompositeCryptoInstance(final ICryptoInstance sourceInstance1,
                                     final ICryptoInstance sourceInstance2,
                                     final String alias,
                                     final RequestContext context,
                                     final Provider provider,
                                     final PrivateKey privateKey,
                                     final PublicKey publicKey) {
            super(alias, context, provider, privateKey, publicKey);
            this.sourceInstance1 = sourceInstance1;
            this.sourceInstance2 = sourceInstance2;
        }

        public ICryptoInstance getSourceInstance1() {
            return sourceInstance1;
        }
        
        public ICryptoInstance getSourceInstance2() {
            return sourceInstance2;
        }

    }
}
