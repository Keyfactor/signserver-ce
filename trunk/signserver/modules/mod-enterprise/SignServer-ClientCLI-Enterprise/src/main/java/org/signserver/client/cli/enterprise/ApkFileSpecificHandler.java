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

import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.MinSdkVersionException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.signserver.client.cli.defaultimpl.AbstractFileSpecificHandler;
import org.signserver.client.cli.defaultimpl.DocumentSignerFactory;
import org.signserver.client.cli.defaultimpl.InputSource;
import org.signserver.client.cli.defaultimpl.OutputCollector;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.module.apk.common.ApkUtils;

/**
 * File-specific handler for APK files.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ApkFileSpecificHandler extends AbstractFileSpecificHandler {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(ApkFileSpecificHandler.class);

    private static final String V1_SIGNATURE = "V1_SIGNATURE";
    private static final String V2_SIGNATURE = "V2_SIGNATURE";
    private static final String V3_SIGNATURE = "V3_SIGNATURE";
    private static final String MIN_SDK_VERSION = "MIN_SDK_VERSION";
    private static final String MAX_SDK_VERSION = "MAX_SDK_VERSION";
    private static final String DEBUGGABLE_APK_PERMITTED =
        "DEBUGGABLE_APK_PERMITTED";
    private static final String V1_SIGNATURE_NAME = "V1_SIGNATURE_NAME";
    
    private ApkPreResponseParser preResponseParser;
    private final Optional<String> workerName;
    private final Optional<Integer> workerId;
    private final Optional<Boolean> v1Signature;
    private final Optional<Boolean> v2Signature;
    private final Optional<Boolean> v3Signature;
    private final Optional<Integer> minSdkVersion;
    /* we don't actually use MAX_SDK_VERSION yet, but reserve it as an integer
     * parameter for future use.
     */
    private final Optional<Integer> maxSdkVersion;
    private final Optional<Boolean> debuggableApkPermitted;
    private final String v1SignatureName;

    private final DocumentSignerFactory signerFactory;
    private final Map<String, Object> requestContext;
    private final Map<String, String> metadata;
    
    public ApkFileSpecificHandler(final File inFile, final File outFile,
                                  final DocumentSignerFactory signerFactory,
                                  final Map<String, Object> requestContext,
                                  final Map<String, String> metadata,
                                  final String workerName,
                                  final Map<String, String> extraOptions) {
        super(inFile, outFile);
        this.workerName = Optional.of(workerName);
        workerId = Optional.empty();
        this.signerFactory = signerFactory;
        this.requestContext = requestContext;
        this.metadata = metadata;
        v1Signature = parseBooleanOption(V1_SIGNATURE,
                                         extraOptions.get(V1_SIGNATURE));
        v2Signature = parseBooleanOption(V2_SIGNATURE,
                                         extraOptions.get(V2_SIGNATURE));
        v3Signature = parseBooleanOption(V3_SIGNATURE,
                                         extraOptions.get(V3_SIGNATURE));
        minSdkVersion =
                parsePositiveIntegerOption(MIN_SDK_VERSION,
                                           extraOptions.get(MIN_SDK_VERSION));
        maxSdkVersion =
                parsePositiveIntegerOption(MAX_SDK_VERSION,
                                           extraOptions.get(MAX_SDK_VERSION));
        debuggableApkPermitted =
                parseBooleanOption(DEBUGGABLE_APK_PERMITTED,
                                   extraOptions.get(DEBUGGABLE_APK_PERMITTED));
        v1SignatureName = extraOptions.get(V1_SIGNATURE_NAME);
    }

    public ApkFileSpecificHandler(final File inFile, final File outFile,
                                  final DocumentSignerFactory signerFactory,
                                  final Map<String, Object> requestContext,
                                  final Map<String, String> metadata,
                                  final int workerId,
                                  final Map<String, String> extraOptions) {
        super(inFile, outFile);
        workerName = Optional.empty();
        this.workerId = Optional.of(workerId);
        this.signerFactory = signerFactory;
        this.requestContext = requestContext;
        this.metadata = metadata;
        v1Signature = parseBooleanOption(V1_SIGNATURE,
                                         extraOptions.get(V1_SIGNATURE));
        v2Signature = parseBooleanOption(V2_SIGNATURE,
                                         extraOptions.get(V2_SIGNATURE));
        v3Signature = parseBooleanOption(V3_SIGNATURE,
                                         extraOptions.get(V3_SIGNATURE));
        minSdkVersion =
                parsePositiveIntegerOption(MIN_SDK_VERSION,
                                           extraOptions.get(MIN_SDK_VERSION));
        maxSdkVersion =
                parsePositiveIntegerOption(MAX_SDK_VERSION,
                                           extraOptions.get(MAX_SDK_VERSION));
        debuggableApkPermitted =
                parseBooleanOption(DEBUGGABLE_APK_PERMITTED,
                                   extraOptions.get(DEBUGGABLE_APK_PERMITTED));
        v1SignatureName = extraOptions.get(V1_SIGNATURE_NAME);
    }

    private Optional<Boolean> parseBooleanOption(final String option,
                                                 final String value) {
        if (StringUtils.isNotBlank(value)) {
            if ("true".equals(value.toLowerCase(Locale.ENGLISH))) {
                return Optional.of(true);
            } else if ("false".equals(value.toLowerCase(Locale.ENGLISH))) {
                return Optional.of(false);
            } else {
                throw new IllegalArgumentException("Illegal boolean value: " +
                                                   value + " for " + option);
            }
        } else {
            return Optional.empty();
        }
    }

    private Optional<Integer> parsePositiveIntegerOption(final String option,
                                                 final String value) {
        if (StringUtils.isNotBlank(value)) {
            try {
                final int intValue = Integer.parseInt(value);

                if (intValue <= 0) {
                    throw new IllegalArgumentException(option + " must be positive");
                }
                return Optional.of(intValue);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Illegal integer value " +
                                                   value + " for " + option);
            }
        } else {
            return Optional.empty();
        }
    }

    private void installProviderIfNeeded() {
        final ApkProvider result;
        Provider p = Security.getProvider(ApkProvider.NAME);
        if (p instanceof ApkProvider) {
            result = (ApkProvider) p;
            if (LOG.isDebugEnabled()) {
                LOG.debug("Using existing provider");
            }
        } else if (p != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found old provider. Re-installing.");
            }
            Security.removeProvider(ApkProvider.NAME);
            result = createProvider();
            Security.addProvider(result);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Did not found our provider: " + p);
            }
            result = createProvider();
            Security.addProvider(result);
        }
    }

    private ApkProvider createProvider() {
        return new ApkProvider();
    }

    @Override
    public boolean isSignatureInputHash() {
        return true;
    }

    @Override
    public InputSource produceSignatureInput(String string) throws NoSuchAlgorithmException, IOException, IllegalRequestException {
        return null;
    }

    private ApkPrivateKey createKeyReference(final String workerName,
                                             final List<Certificate> certChain) {
        final Certificate signerCert = certChain.get(0);
        final String alg = signerCert.getPublicKey().getAlgorithm();
        
        switch (alg) {
            case "RSA":
                return new ApkRsaPrivateKey(workerName, signerFactory,
                                            requestContext, metadata);
            case "EC":
                return new ApkEcPrivateKey(workerName, signerFactory,
                                           requestContext, metadata);
            default:
                throw new IllegalArgumentException("Unsupported key algorithm: " + alg);
        }
    }

    private ApkPrivateKey createKeyReference(final int workerId,
                                             final List<Certificate> certChain) {
        final Certificate signerCert = certChain.get(0);
        final String alg = signerCert.getPublicKey().getAlgorithm();
        
        switch (alg) {
            case "RSA":
                return new ApkRsaPrivateKey(workerId, signerFactory,
                                            requestContext, metadata);
            case "EC":
                return new ApkEcPrivateKey(workerId, signerFactory,
                                           requestContext, metadata);
            default:
                throw new IllegalArgumentException("Unsupported key algorithm: " + alg);
        }
    }
    
    @Override
    public void assemble(OutputCollector oc) throws IOException, IllegalArgumentException {
        final List<com.android.apksig.ApkSigner.SignerConfig> signerConfigs = new ArrayList<>();
        final Set<String> sfNames = new HashSet<String>();

        installProviderIfNeeded();
        
        try {
            final List<Certificate> signerCertChain = preResponseParser.getSignerCertificateChain();

            if (signerCertChain == null || signerCertChain.isEmpty()) {
                throw new IllegalArgumentException("No signer certificate chain in pre-response");
            }
            final ApkPrivateKey privKey =
                    workerName.isPresent() ? createKeyReference(workerName.get(),
                                                                signerCertChain) :
                                             createKeyReference(workerId.get(),
                                                                signerCertChain);
            signerConfigs.add(createSignerConfig(signerCertChain, sfNames,
                                                 v1SignatureName, privKey));

            for (int i = 0; i < preResponseParser.getNumberOfOtherSigners(); i++) {
                final List<Certificate> certChainForOtherSigner =
                        preResponseParser.getCertificateChainForOtherSigner(i);
                final ApkPrivateKey otherSignerPrivKey =
                        createKeyReference(preResponseParser.getNameForOtherSigner(i),
                                           certChainForOtherSigner);

                signerConfigs.add(createSignerConfig(certChainForOtherSigner,
                                                     sfNames, v1SignatureName,
                                                     otherSignerPrivKey));
            }

            com.android.apksig.ApkSigner.Builder apkSignerBuilder =
                new com.android.apksig.ApkSigner.Builder(signerConfigs)
                        .setInputApk(getInFile())
                        .setOutputApk(getOutFile())
                        .setOtherSignersSignaturesPreserved(false);
            if (v1Signature.isPresent()) {
                apkSignerBuilder.setV1SigningEnabled(v1Signature.get());
            }
            if (v2Signature.isPresent()) {
                apkSignerBuilder.setV2SigningEnabled(v2Signature.get());
            }
            if (v3Signature.isPresent()) {
                apkSignerBuilder.setV3SigningEnabled(v3Signature.get());
            }
            if (debuggableApkPermitted.isPresent()) {
                apkSignerBuilder.setDebuggableApkPermitted(debuggableApkPermitted.get());
            }
            if (minSdkVersion.isPresent()) {
                apkSignerBuilder.setMinSdkVersion(minSdkVersion.get());
            }
            
            final SigningCertificateLineage lineage =
                    preResponseParser.getLineageFileContent();

            if (lineage != null) {
                apkSignerBuilder.setSigningCertificateLineage(lineage);
            }

            for (final Provider prov : Security.getProviders()) {
                LOG.debug("provider: " + prov.getName());
            }
            
            com.android.apksig.ApkSigner apkSigner = apkSignerBuilder.build();
            try {
                apkSigner.sign();
            } catch (MinSdkVersionException e) {
                throw new IllegalArgumentException(
                          "Failed to determine APK's minimum supported platform version",
                           e);
            } catch (ApkFormatException | NoSuchAlgorithmException |
                     InvalidKeyException | SignatureException |
                     IllegalStateException ex) {
                LOG.error("apk signing error", ex);
                throw new IOException("apk signing error", ex);
            }
        } catch (CertificateParsingException e) {
            throw new IOException("Failed to parse signer certificate from pre-response",
                                  e);
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            LOG.error("Failed to instanciate keystore", e);
            throw new IOException("Failed to instanciate keystore", e);
        } catch (SignServerException e) {
            throw new IOException("Failed to create signer config", e);
        }
    }

    @Override
    public void assemblePreResponse(OutputCollector oc) throws IOException, IllegalArgumentException {
        preResponseParser = new ApkPreResponseParser(oc.toByteArray());
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Signer CN: " + preResponseParser.getSignerCertificateChain().get(0).toString());
            }
        } catch (CertificateParsingException e) {
            LOG.error("Failed to parse signer certificate chain", e);
        }
    }

    @Override
    public InputSource producePreRequestInput() throws IOException, IllegalRequestException {
        return new InputSource(new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8)),
                                       0, new HashMap<>());
    }

    @Override
    public String getFileTypeIdentifier() {
        return "APK";
    }

    /**
     * Create the config for the signer given by the crypto instance.
     * @param cryptoInstance to create config for
     * @param sfNames existing v1 signature names
     * @param requestContext
     * @return the signer config
     * @throws SignServerException 
     */
    private com.android.apksig.ApkSigner.SignerConfig createSignerConfig(final List<Certificate> signerCertificateChain, 
            final Set<String> sfNames, final String v1SignatureName,
            final ApkPrivateKey privKey) throws SignServerException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        final Certificate signerCert = signerCertificateChain.get(0);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SigningCert: " + ((X509Certificate) signerCert).getSubjectDN());
        }
        
        // Get name to use for the signature
        String signatureName;

        if (v1SignatureName != null) {
            signatureName = v1SignatureName;
        } else {
            // Fallback to use the common name or the whole DN
            final String dn = CertTools.getSubjectDN(signerCert);
            signatureName = CertTools.getPartFromDN(dn, "CN");
            if (signatureName == null) {
                signatureName = dn;
            }
        }
        
        signatureName = ApkUtils.createUniqueSignatureFileName(ApkUtils.convertToValidSignatureName(signatureName), sfNames);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating SignerConfig for " + signatureName);
        }

        com.android.apksig.ApkSigner.SignerConfig signerConfig =
                new com.android.apksig.ApkSigner.SignerConfig.Builder(
                        signatureName, privKey,
                        ApkUtils.toX509List(signerCertificateChain))
                        .build();

        return signerConfig;
    }
    
}
