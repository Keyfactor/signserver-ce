/** ***********************************************************************
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
 ************************************************************************ */
package org.signserver.module.openpgp.signer;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.persistence.EntityManager;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.sig.RevocationReasonTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPPrivateKey;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.common.CompileTimeSettings;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.NoSuchAliasException;
import org.signserver.common.OpenPgpCertReqData;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.openpgp.utils.ClearSignedFileProcessorUtils;
import org.signserver.server.IServices;
import org.signserver.server.ServicesImpl;
import org.signserver.server.WorkerContext;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.PROPERTY_SELFSIGNED_VALIDITY;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import static org.signserver.server.cryptotokens.ICryptoTokenV4.PARAM_INCLUDE_DUMMYCERTIFICATE;
import org.signserver.server.signers.BaseSigner;

/**
 * Base class for OpenPGP & DebinanDpkgSig signing. To be extended for specific implementations.
 *
 * @author Vinay Singh
 * @Version $Id$
 */
public abstract class BaseOpenPGPSigner extends BaseSigner {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(BaseOpenPGPSigner.class);
    
    // Worker properties
    public static final String PROPERTY_PGPPUBLICKEY = "PGPPUBLICKEY";
    public static final String PROPERTY_DIGEST_ALGORITHM = "DIGEST_ALGORITHM";
    public static final String PROPERTY_GENERATE_REVOCATION_CERTIFICATE
            = "GENERATE_REVOCATION_CERTIFICATE";
    
    // Default values
    private static final boolean DEFAULT_GENERATE_REVOCATION_CERTIFICATE = false;
    private static final int DEFAULT_DIGEST_ALGORITHM = PGPUtil.SHA256;
    
    // Configuration values
    private PGPPublicKey pgpCertificate;
    private boolean generateRevocationCertificate;
    private Long selfsignedValidity;
    protected int digestAlgorithm = DEFAULT_DIGEST_ALGORITHM;  
           
    // Configuration errors
    protected final LinkedList<String> configErrors = new LinkedList<>();         
        
    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        // Optional property DIGEST_ALGORITHM
        final String digestAlgorithmValue = config.getProperty(PROPERTY_DIGEST_ALGORITHM);
        if (digestAlgorithmValue != null) {
            try {
                if (StringUtils.isNumeric(digestAlgorithmValue.trim())) {
                    digestAlgorithm = Integer.parseInt(digestAlgorithmValue.trim());
                } else {
                    digestAlgorithm = OpenPGPUtils.getDigestFromString(digestAlgorithmValue.trim());
                }
            } catch (NumberFormatException | PGPException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Illegal value for " + PROPERTY_DIGEST_ALGORITHM, ex);
                }
                configErrors.add("Illegal value for " + PROPERTY_DIGEST_ALGORITHM + ". Possible values are numeric or textual OpenPGP Hash Algorithms");
            }
        }

        // Optional property PGPPUBLICKEY
        final String publicKeyValue = config.getProperty(PROPERTY_PGPPUBLICKEY);
        if (publicKeyValue != null) {
            try {
                final List<PGPPublicKey> keys = OpenPGPUtils.parsePublicKeys(publicKeyValue);
                if (keys.isEmpty()) {
                    configErrors.add("No public key found in worker property " + PROPERTY_PGPPUBLICKEY);
                } else {
                    if (keys.size() > 1) {
                        LOG.warn("More than one public keys in PGPPUBLICKEY property.");
                    }
                    pgpCertificate = keys.get(0);
                }
            } catch (IOException | PGPException ex) {
                configErrors.add("Unable to parse public key in worker property " + PROPERTY_PGPPUBLICKEY + ": " + ex.getLocalizedMessage());
            }
        }
        
        // Optional property GENERATE_REVOCATION_CERTIFICATE
        final String generateRevocationCertificateValue =
                config.getProperty(PROPERTY_GENERATE_REVOCATION_CERTIFICATE,
                                   Boolean.toString(DEFAULT_GENERATE_REVOCATION_CERTIFICATE));

        if (Boolean.TRUE.toString().equalsIgnoreCase(generateRevocationCertificateValue)) {
            generateRevocationCertificate = true;
        } else if (Boolean.FALSE.toString().equalsIgnoreCase(generateRevocationCertificateValue)) {
            generateRevocationCertificate = false;
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Illegal value for " +
                          PROPERTY_GENERATE_REVOCATION_CERTIFICATE + ": " +
                          generateRevocationCertificateValue);
            }
            configErrors.add("Illegal value for " +
                             PROPERTY_GENERATE_REVOCATION_CERTIFICATE +
                             ". Specify boolean (true or false)");
        }
        
        // Optional property SELFSIGNED_VALIDITY
        final String validityValue = config.getProperty(PROPERTY_SELFSIGNED_VALIDITY);
        if (validityValue != null) {
            try {
                selfsignedValidity = Long.parseLong(validityValue);
            } catch (NumberFormatException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Illegal value for " + PROPERTY_SELFSIGNED_VALIDITY, ex);
                }
                configErrors.add("Illegal value for " + PROPERTY_SELFSIGNED_VALIDITY + ". Please enter a numberic value.");
            }
        }
    }    
    
    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, String keyAlias, IServices services) throws CryptoTokenOfflineException, NoSuchAliasException {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">genCertificateRequest");
        }

        final RequestContext context = new RequestContext(false);
        context.setServices(services);

        ICryptoInstance crypto = null;
        ICryptoTokenV4 token = null;
        try {
            token = getCryptoToken(services);

            if (token == null) {
                throw new CryptoTokenOfflineException("Crypto token offline");
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found a crypto token of type: " + token.getClass().getName());
            }

            // Acquire crypto instance
            final Map<String, Object> params = new HashMap<>();
            params.put(PARAM_INCLUDE_DUMMYCERTIFICATE, true);
            crypto = token.acquireCryptoInstance(keyAlias, params, context);

            PKCS10CertReqInfo reqInfo = (PKCS10CertReqInfo) info;
            
            final JcaPGPKeyConverter conv = new JcaPGPKeyConverter();
            final X509Certificate x509Cert = (X509Certificate) getSigningCertificate(crypto);
            final boolean generateForDefaultKey = keyAlias.equals(config.getProperty("DEFAULTKEY"));
            final PGPPublicKey pgpPublicKey =
                    pgpCertificate != null && generateForDefaultKey ?
                    pgpCertificate :
                    conv.getPGPPublicKey(OpenPGPUtils.getKeyAlgorithm(x509Cert),
                                         x509Cert.getPublicKey(),
                                         x509Cert.getNotBefore());

            PGPSignatureGenerator generator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpPublicKey.getAlgorithm(), OpenPGPUtils.getHashAlgorithm(reqInfo.getSignatureAlgorithm())).setProvider(crypto.getProvider()).setDigestProvider("BC"));

            generator.init(generateRevocationCertificate ?
                           PGPSignature.KEY_REVOCATION :
                           PGPSignature.DEFAULT_CERTIFICATION,
                           new JcaPGPPrivateKey(pgpPublicKey, crypto.getPrivateKey()));

            PGPSignatureSubpacketGenerator subGenerator = new PGPSignatureSubpacketGenerator();
            PGPSignatureSubpacketGenerator nonHashedSubGenerator = new PGPSignatureSubpacketGenerator();
            
            // Validity time
            if (selfsignedValidity != null) {    
                subGenerator.setKeyExpirationTime(true, selfsignedValidity);
            } else {
                LOG.error("No SELFSIGNED_VALIDITY so not setting any expiration");
            }

            if (generateRevocationCertificate) {
                // TODO: make the reason and description configurable?
                subGenerator.setRevocationReason(false,
                                                 RevocationReasonTags.NO_REASON,
                                                 "");
                nonHashedSubGenerator.setIssuerKeyID(false, pgpPublicKey.getKeyID());
            }

            generator.setHashedSubpackets(subGenerator.generate());
            generator.setUnhashedSubpackets(nonHashedSubGenerator.generate());

            // Generate and add certification
            final OpenPgpCertReqData result;
            if (generateRevocationCertificate) {
                final PGPSignature certification = generator.generateCertification(pgpPublicKey);
                final String revocationHeader = getRevocationHeader(pgpPublicKey);
                result = new OpenPgpCertReqData(certification, true, ".rev",
                                                revocationHeader,
                                                "This is a revocation certificate");
            } else {
                final PGPSignature certification = generator.generateCertification(reqInfo.getSubjectDN(), pgpPublicKey);
                final PGPPublicKey certifiedKey = PGPPublicKey.addCertification(pgpPublicKey, reqInfo.getSubjectDN(), certification);
                result = new OpenPgpCertReqData(certifiedKey);
            }

            if (LOG.isTraceEnabled()) {
                LOG.trace("<genCertificateRequest");
            }

            return result;
        } catch (SignServerException e) {
            LOG.error("FAILED_TO_GET_CRYPTO_TOKEN_" + e.getMessage());
            throw new CryptoTokenOfflineException(e);
        } catch (InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter | IllegalRequestException | PGPException | IOException ex) {
            throw new CryptoTokenOfflineException(ex);
        } finally {
            if (token != null) {
                token.releaseCryptoInstance(crypto, context);
            }
        }
    }
    
    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, boolean defaultKey) throws CryptoTokenOfflineException, NoSuchAliasException {
        return genCertificateRequest(info, explicitEccParameters, defaultKey, new ServicesImpl());
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, boolean defaultKey, IServices services) throws CryptoTokenOfflineException, NoSuchAliasException {
        return genCertificateRequest(certReqInfo, explicitEccParameters, defaultKey ? config.getProperty("DEFAULTKEY") : config.getProperty("NEXTCERTSIGNKEY"), services);
    }
    
    private String getRevocationHeader(final PGPPublicKey publicKey) {
        final StringBuilder sb = new StringBuilder();

        sb.append("This is a revocation certificate for the OpenPGP key:")
          .append("\n")
          .append("Fingerprint: ").append(Hex.toHexString(publicKey.getFingerprint()).toUpperCase(Locale.ENGLISH))
          .append("\n")
          .append("User IDs:").append("\n");

        final Iterator userIDs = publicKey.getUserIDs();
        while (userIDs.hasNext()) {
            Object o = userIDs.next();
            if (o instanceof String) {
                sb.append("   ").append((String) o).append("\n");
            }
        }

        sb.append("\n")
          .append("To avoid an accidental use of this file,")
          .append("\n")
          .append("a colon has been inserted before the five dashes.")
          .append("\n")
          .append("Remove this colon before using the revocation certificate.")
          .append("\n")
          .append(":");

        return sb.toString();
    }
    
    @Override
    public List<String> getFatalErrors(final IServices services) {
        final List<String> result = new LinkedList<>();
        result.addAll(super.getFatalErrors(services));
        result.addAll(configErrors);

        // Check that PGPPUBLICKEY matches key
        if (pgpCertificate != null) {
            try {
                final X509Certificate signerCert = (X509Certificate) getSigningCertificate(services);
                final JcaPGPKeyConverter conv = new JcaPGPKeyConverter();
                final PGPPublicKey pgpPublicKey = conv.getPGPPublicKey(OpenPGPUtils.getKeyAlgorithm(signerCert), signerCert.getPublicKey(), signerCert.getNotBefore());

                if (!Arrays.equals(pgpPublicKey.getPublicKeyPacket().getKey().getEncoded(), pgpCertificate.getPublicKeyPacket().getKey().getEncoded())) {
                    result.add("Configured " + PROPERTY_PGPPUBLICKEY + " not matching the key");
                }
            } catch (CryptoTokenOfflineException ex) {
                if (isCryptoTokenActive(services)) {
                    result.add("No signer certificate available");
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signer " + workerId + ": Could not get signer certificate: " + ex.getMessage());
                }
            } catch (SignServerException | PGPException ex) {
                result.add("Unable to parse OpenPGP public key: " + ex.getMessage());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unable to parse OpenPGP public key", ex);
                }
            }
        }

        return result;
    }
    
    @Override
    public WorkerStatusInfo getStatus(final List<String> additionalFatalErrors, final IServices services) {
        WorkerStatusInfo status = (WorkerStatusInfo) super.getStatus(additionalFatalErrors, services);

        final RequestContext context = new RequestContext(true);
        context.setServices(services);
        ICryptoInstance crypto = null;
        try {
            final Map<String, Object> params = new HashMap<>();
            params.put(PARAM_INCLUDE_DUMMYCERTIFICATE, true);
            crypto = acquireDefaultCryptoInstance(params, context);

            X509Certificate signerCertificate = (X509Certificate) crypto.getCertificate();
            if (signerCertificate != null) {

                final JcaPGPKeyConverter conv = new JcaPGPKeyConverter();
                X509Certificate x509Cert = (X509Certificate) getSigningCertificate(crypto);

                PGPPublicKey pgpPublicKey = conv.getPGPPublicKey(OpenPGPUtils.getKeyAlgorithm(x509Cert), x509Cert.getPublicKey(), x509Cert.getNotBefore());

                status.getCompleteEntries().add(new WorkerStatusInfo.Entry("Key ID", OpenPGPUtils.formatKeyID(pgpPublicKey.getKeyID())));
                status.getCompleteEntries().add(new WorkerStatusInfo.Entry("Primary key fingerprint", Hex.toHexString(pgpPublicKey.getFingerprint()).toUpperCase(Locale.ENGLISH)));

                // Empty public key
                if (pgpCertificate != null) {
                    ByteArrayOutputStream bout = new ByteArrayOutputStream();
                    ArmoredOutputStream out2 = new ArmoredOutputStream(bout);
                    pgpCertificate.encode(out2);
                    out2.close();

                    status.getCompleteEntries().add(new WorkerStatusInfo.Entry("PGP Public key", new String(bout.toByteArray(), StandardCharsets.US_ASCII)));

                    status.getCompleteEntries().add(new WorkerStatusInfo.Entry("PGP Key ID", OpenPGPUtils.formatKeyID(pgpCertificate.getKeyID())));

                    final StringBuilder sb = new StringBuilder();

                    int algorithm = pgpCertificate.getAlgorithm();
                    int bitStrength = pgpCertificate.getBitStrength();
                    Date creationTime = pgpCertificate.getCreationTime();
                    long validSeconds = pgpCertificate.getValidSeconds();
                    boolean masterKey = pgpCertificate.isMasterKey();
                    int version = pgpCertificate.getVersion();

                    sb.append("Master key: ").append(masterKey).append("\n");
                    sb.append("Version: ").append(version).append("\n");
                    sb.append("Algorithm: ").append(algorithm).append("\n");
                    sb.append("Bit length: ").append(bitStrength).append("\n");
                    sb.append("Creation time: ").append(creationTime).append("\n");
                    sb.append("Expire time: ").append(validSeconds == 0 ? "n/a" : new Date(creationTime.getTime() + 1000L * validSeconds)).append("\n");

                    sb.append("User IDs:").append("\n");
                    Iterator userIDs = pgpCertificate.getUserIDs();
                    while (userIDs.hasNext()) {
                        Object o = userIDs.next();
                        if (o instanceof String) {
                            sb.append("   ").append((String) o).append("\n");
                        }
                    }

                    sb.append("Signatures:").append("\n");
                    Iterator signatures = pgpCertificate.getSignatures();
                    while (signatures.hasNext()) {
                        Object o = signatures.next();
                        if (o instanceof PGPSignature) {
                            PGPSignature sig = (PGPSignature) o;
                            sb.append("   ")
                                    .append(sig.getCreationTime())
                                    .append(" by key ID ")
                                    .append(String.format("%X", sig.getKeyID())).append("\n");
                        }
                    }

                    status.getCompleteEntries().add(new WorkerStatusInfo.Entry("PGP Public key", sb.toString()));
                }

            }
        } catch (CryptoTokenOfflineException e) {} // the error will have been picked up by getCryptoTokenFatalErrors already
        catch (InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter | IllegalRequestException | SignServerException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unable to obtain certificate from token", ex);
            }
        } catch (PGPException ex) {
            LOG.error("Unable to parse PGP public key", ex);
        } catch (IOException ex) {
            LOG.error("Unable to encode PGP public key", ex);
        } finally {
            if (crypto != null) {
                try {
                    releaseCryptoInstance(crypto, context);
                } catch (SignServerException ex) {
                    LOG.warn("Unable to release crypto instance", ex);
                }
            }
        }

        return status;
    }
    
    @Override
    protected ICryptoInstance acquireDefaultCryptoInstance(Map<String, Object> params, String alias, RequestContext context) throws CryptoTokenOfflineException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter, IllegalRequestException, SignServerException {
        final Map<String, Object> newParams = new HashMap<>(params);
        newParams.put(PARAM_INCLUDE_DUMMYCERTIFICATE, true);
        return super.acquireDefaultCryptoInstance(newParams, alias, context);
    }
    
    /**
     * Sign the given data and produce output in clear text format.
     *
     * @param pgpPrivateKey PGP  private key
     * @param pgpPublicKey PGP public key
     * @param generator signature generator
     * @param in InputStream containing data to be signed
     * @param out OutputStream holder for signature output 
     * @param digestAlgorithm used to digest the data before signing
     * @throws org.signserver.common.SignServerException
     *
     */
    protected void signClearText(final PGPPrivateKey pgpPrivateKey, final PGPPublicKey pgpPublicKey, final PGPSignatureGenerator generator, final InputStream in, final OutputStream out, int digestAlgorithm) throws SignServerException {
        try {
            generator.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, pgpPrivateKey);

            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

            Iterator it = pgpPublicKey.getUserIDs();
            if (it.hasNext()) {
                spGen.setSignerUserID(false, (String) it.next());
                generator.setHashedSubpackets(spGen.generate());
            }

            try (InputStream fIn = new BufferedInputStream(in);
                    ArmoredOutputStream aOut = new ArmoredOutputStream(out)) {
                aOut.setHeader(ArmoredOutputStream.VERSION_HDR, CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_VERSION));
                aOut.beginClearText(digestAlgorithm);
                ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
                int lookAhead = ClearSignedFileProcessorUtils.readInputLine(lineOut, fIn);
                ClearSignedFileProcessorUtils.processLine(aOut, generator, lineOut.toByteArray());
                if (lookAhead != -1) {
                    do {
                        lookAhead = ClearSignedFileProcessorUtils.readInputLine(lineOut, lookAhead, fIn);

                        generator.update((byte) '\r');
                        generator.update((byte) '\n');

                        ClearSignedFileProcessorUtils.processLine(aOut, generator, lineOut.toByteArray());
                    } while (lookAhead != -1);
                }

                // Add new line before signature if needed
                byte[] lastBytes = lineOut.toByteArray();
                if (lastBytes.length > 0 && (lastBytes[lastBytes.length - 1] != '\r' && lastBytes[lastBytes.length - 1] != '\n')) {
                    aOut.write("\r\n".getBytes(StandardCharsets.US_ASCII));
                }

                aOut.endClearText();
                BCPGOutputStream bOut = new BCPGOutputStream(aOut);
                generator.generate().encode(bOut);
            } catch (IOException ex) {
                throw new SignServerException("Encoding error", ex);
            } catch (SignatureException ex) {
                throw new SignServerException("SignatureException", ex);
            }
        } catch (PGPException ex) {
            throw new SignServerException("PGP exception", ex);
        }
    }

}
