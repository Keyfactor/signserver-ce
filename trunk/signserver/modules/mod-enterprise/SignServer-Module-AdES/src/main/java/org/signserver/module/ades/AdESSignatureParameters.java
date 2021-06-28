/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.ades;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.apache.log4j.Logger;

import static org.signserver.module.ades.AdESSignatureLevel.TIMESTAMPING_REQUIRED;

/**
 * A delegate-proxy class to combine PAdESSignatureParameters and XAdESSignatureParameters and build the corresponding
 * instance.
 *
 * It contains a <b>single instance</b> of PAdESSignatureParameters or XAdESSignatureParameters,
 * that should be used  during all stages of signing.
 *
 * @author Andrey Sergeev
 * @version $Id$
 */
public class AdESSignatureParameters {

    private static final Logger LOG = Logger.getLogger(AdESSignatureParameters.class);

    /** Extra space to add to the content size if content time-stamp is enabled. **/
    private static final int EXTRA_SIZE_FOR_CONTENT_TST = 5192;

    private AdESSignatureFormat adESSignatureFormat;
    private AdESSignatureLevel adESSignatureLevel;
    private SignatureAlgorithm signatureAlgorithm;
    private DigestAlgorithm digestAlgorithm;
    private CertificateToken signingCertificate;
    private List<CertificateToken> certificateTokens;
    private DigestAlgorithm tsaDigestAlgorithm;
    private boolean addContentTimestamp;
    private List<TimestampToken> contentTimestamps = new ArrayList<>();
    private Integer contentSize;                        // Corresponds to PAdESSignatureParameters.signatureSize
    private SignaturePackaging signaturePackaging;
    // Resulting instance one at a time
    private PAdESSignatureParameters pAdESSignatureParameters;
    private XAdESSignatureParameters xAdESSignatureParameters;
    private int extraSignatureSpace;

    // Restricted constructor
    private AdESSignatureParameters() {
    }

    public static AdESSignatureParameters builder() {
        return new AdESSignatureParameters();
    }

    /**
     * With signature format PAdES or XAdES.
     * @param adESSignatureFormat signature format.
     * @return current instance of AdESSignatureParameters.
     * @see AdESSignatureFormat#PAdES
     * @see AdESSignatureFormat#XAdES
     */
    public AdESSignatureParameters withAdESSignatureFormat(final AdESSignatureFormat adESSignatureFormat) {
        this.adESSignatureFormat = adESSignatureFormat;
        return this;
    }

    /**
     * With signature level -B, -T, -LT or -LTA.
     * @param adESSignatureLevel signature level.
     * @return current instance of AdESSignatureParameters.
     * @see PAdESSignatureParameters#setSignatureLevel(SignatureLevel)
     * @see XAdESSignatureParameters#setSignatureLevel(SignatureLevel)
     */
    public AdESSignatureParameters withAdESSignatureLevel(final AdESSignatureLevel adESSignatureLevel) {
        this.adESSignatureLevel = adESSignatureLevel;
        return this;
    }

    /**
     * With signature algorithm.
     * @param signatureAlgorithm signature algorithm.
     * @return current instance of AdESSignatureParameters.
     * @see PAdESSignatureParameters#setDigestAlgorithm(DigestAlgorithm)
     * @see XAdESSignatureParameters#setDigestAlgorithm(DigestAlgorithm)
     */
    public AdESSignatureParameters withSignatureAlgorithm(final SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    /**
     * With digest algorithm.
     * @param digestAlgorithm digest algorithm.
     * @return current instance of AdESSignatureParameters.
     * @see PAdESSignatureParameters#setDigestAlgorithm(DigestAlgorithm)
     * @see XAdESSignatureParameters#setDigestAlgorithm(DigestAlgorithm)
     */
    public AdESSignatureParameters withDigestAlgorithm(final DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
        return this;
    }

    /**
     * With signing certificate.
     * @param signingCertificate signing certificate.
     * @return current instance of AdESSignatureParameters.
     * @see PAdESSignatureParameters#setSigningCertificate(CertificateToken)
     * @see XAdESSignatureParameters#setSigningCertificate(CertificateToken)
     */
    public AdESSignatureParameters withSigningCertificate(final CertificateToken signingCertificate) {
        this.signingCertificate = signingCertificate;
        return this;
    }

    /**
     * With certificate chain.
     * @param certificateTokens list of certificate tokens.
     * @return current instance of AdESSignatureParameters.
     * @see PAdESSignatureParameters#setCertificateChain(CertificateToken...)
     * @see XAdESSignatureParameters#setCertificateChain(CertificateToken...)
     */
    public AdESSignatureParameters withCertificateChain(final List<CertificateToken> certificateTokens) {
        this.certificateTokens = certificateTokens;
        return this;
    }

    /**
     * With flag of adding the content timestamp.
     * @param addContentTimestamp the flag of adding the content timestamp.
     * @return current instance of AdESSignatureParameters.
     */
    public AdESSignatureParameters withAddContentTimestamp(final boolean addContentTimestamp) {
        this.addContentTimestamp = addContentTimestamp;
        return this;
    }

    /**
     * With TSA digest algorithm.
     * @param tsaDigestAlgorithm TSA digest algorithm.
     * @return current instance of AdESSignatureParameters.
     * @see PAdESSignatureParameters#setContentTimestampParameters(CAdESTimestampParameters)
     * @see XAdESSignatureParameters#setContentTimestampParameters(SerializableTimestampParameters)
     */
    public AdESSignatureParameters withTSADigestAlgorithm(final DigestAlgorithm tsaDigestAlgorithm) {
        this.tsaDigestAlgorithm = tsaDigestAlgorithm;
        return this;
    }

    /**
     * With Signature Packaging (ENVELOPED, ENVELOPING, DETACHED, INTERNALLY_DETACHED).
     * @param signaturePackaging signature packaging.
     * @return current instance of AdESSignatureParameters.
     * @see PAdESSignatureParameters#setSignaturePackaging(SignaturePackaging)
     * @see XAdESSignatureParameters#setSignaturePackaging(SignaturePackaging)
     * @see SignaturePackaging#DETACHED
     * @see SignaturePackaging#ENVELOPED
     * @see SignaturePackaging#ENVELOPING
     * @see SignaturePackaging#INTERNALLY_DETACHED
     */
    public AdESSignatureParameters withSignaturePackaging(final SignaturePackaging signaturePackaging) {
        this.signaturePackaging = signaturePackaging;
        return this;
    }

    /**
     * With Extra Signature Space.
     *
     * @param extraSignatureSpace extra signature space.
     * @return current instance of AdESSignatureParameters.
     * @see PAdESSignatureParameters#setContentSize(int)
     */
    public AdESSignatureParameters withExtraSignatureSpace(final int extraSignatureSpace) {
        this.extraSignatureSpace = extraSignatureSpace;
        return this;
    }

    /**
     * Sets the content timestamps.
     * @param contentTimestamps content timestamps.
     * @see PAdESSignatureParameters#setContentTimestamps(List)
     * @see XAdESSignatureParameters#setContentTimestamps(List)
     */
    public void setContentTimestamps(final List<TimestampToken> contentTimestamps) {
        // We need to update the parameter instances if they have already been created at this point
        // (i.e. by call to AdESService.getContentTimestamp())
        if (pAdESSignatureParameters != null) {
            this.contentTimestamps = pAdESSignatureParameters.getContentTimestamps();
            this.contentTimestamps.addAll(contentTimestamps);
            pAdESSignatureParameters.setContentTimestamps(contentTimestamps);
        }
        if (xAdESSignatureParameters != null) {
            this.contentTimestamps = xAdESSignatureParameters.getContentTimestamps();
            this.contentTimestamps.addAll(contentTimestamps);
            xAdESSignatureParameters.setContentTimestamps(contentTimestamps);
        }
    }

    // TODO Doesn't exist for XAdES
    public void setContentSize(final int contentSize) {
        this.contentSize = contentSize;
        if (pAdESSignatureParameters != null || xAdESSignatureParameters != null) {
            throw new IllegalStateException("Too late to call setContentSize() as the parameters has already been used");
        }
    }

    // TODO Doesn't exist for XAdES
    /**
     * Returns the content size of PAdESSignatureParameters.
     * @return the content size of PAdESSignatureParameters.
     * @see PAdESSignatureParameters#getContentSize()
     */
    public int getContentSize() {
        if(contentSize == null && adESSignatureFormat == AdESSignatureFormat.PAdES) {
            return new PAdESSignatureParameters().getContentSize();
        }
        else if(contentSize != null) {
            return contentSize;
        }
        return 0;
    }

    /**
     * Returns the digest algorithm of the corresponding instance.
     * @return the digest algorithm of the corresponding instance.
     * @see PAdESSignatureParameters#getDigestAlgorithm()
     * @see XAdESSignatureParameters#getDigestAlgorithm()
     */
    public DigestAlgorithm getDigestAlgorithm() {
        if(pAdESSignatureParameters != null) {
            return pAdESSignatureParameters.getDigestAlgorithm();
        }
        if(xAdESSignatureParameters != null) {
            return xAdESSignatureParameters.getDigestAlgorithm();
        }
        return null;
    }

    /**
     * Returns the MaskGenerationFunction if signature algorithm is defined, null otherwise.
     * @return the MaskGenerationFunction if signature algorithm is defined, null otherwise.
     */
    public MaskGenerationFunction getMaskGenerationFunction() {
        if(signatureAlgorithm != null) {
            return signatureAlgorithm.getMaskGenerationFunction();
        }
        return null;
    }

    /**
     * Builds the corresponding instance of PAdESSignatureParameters or XAdESSignatureParameters.
     * @return current instance of AdESSignatureParameters.
     */
    public AdESSignatureParameters build() {
        // TODO Extra validation?
        // Validate
        Objects.requireNonNull(adESSignatureFormat, "AdESSignatureFormat is required.");
        Objects.requireNonNull(adESSignatureLevel, "AdESSignatureLevel is required.");
        Objects.requireNonNull(signingCertificate, "Signing certificate is required.");
        Objects.requireNonNull(certificateTokens, "Certificate chain is required.");
        // Build
        switch (adESSignatureFormat) {
            case PAdES:
                // Preparing parameters for the PAdES signature
                final PAdESSignatureParameters pAdESSigParameters = new PAdESSignatureParameters();
                // We choose the level of the signature (-B, -T, -LT, -LTA).
                pAdESSigParameters.setSignatureLevel(getSignatureLevel());
                // We don't set the signature packaging
                // We set the digest algorithm to use with the signature algorithm. You must use the
                // same parameter when you invoke the method sign on the token. The default value is
                // SHA256
                if (signatureAlgorithm != null) {
                    pAdESSigParameters.setDigestAlgorithm(signatureAlgorithm.getDigestAlgorithm());
                    pAdESSigParameters.setEncryptionAlgorithm(signatureAlgorithm.getEncryptionAlgorithm());
                    pAdESSigParameters.setMaskGenerationFunction(signatureAlgorithm.getMaskGenerationFunction());
                } else if (digestAlgorithm != null) {
                    pAdESSigParameters.setDigestAlgorithm(digestAlgorithm);
                }
                // We set the signing certificate
                pAdESSigParameters.setSigningCertificate(signingCertificate);
                // We set the certificate chain
                pAdESSigParameters.setCertificateChain(certificateTokens);
                //
                if (TIMESTAMPING_REQUIRED.contains(adESSignatureLevel)) {
                    pAdESSigParameters.setSignatureTimestampParameters(new PAdESTimestampParameters(tsaDigestAlgorithm));
                }
                if (addContentTimestamp) {
                    pAdESSigParameters.setContentTimestamps(contentTimestamps);
                    // Increase the expected size of the signature to have room for the additional time-stamp
                    // Note that we can not do this after receiving the time-stamp token as if we change the
                    // value we invalidate the signature
                    // This also means that we could fail at this point and in the future we might want to
                    // consider trying again if the signature become to large
                    setContentSize(getContentSize() + EXTRA_SIZE_FOR_CONTENT_TST);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Adding " + EXTRA_SIZE_FOR_CONTENT_TST + " bytes for TSA");
                    }
                }
                // Get the default for PAdESSignatureParameters (signatureSize = 9472)
                if (contentSize != null) {
                    pAdESSigParameters.setContentSize(contentSize);
                }
                if (extraSignatureSpace > 0) {
                    pAdESSigParameters.setContentSize(getContentSize() + extraSignatureSpace);
                }
                pAdESSignatureParameters = pAdESSigParameters;
                break;
            case XAdES:
                // Preparing parameters for the XAdES signature
                final XAdESSignatureParameters xAdESSigParameters = new XAdESSignatureParameters();
                // We choose the level of the signature (-B, -T, -LT, -LTA).
                xAdESSigParameters.setSignatureLevel(getSignatureLevel());
                // We choose the type of the signature packaging (ENVELOPED, ENVELOPING, DETACHED).
                xAdESSigParameters.setSignaturePackaging(signaturePackaging);
                // We set the digest algorithm to use with the signature algorithm. You must use the
                // same parameter when you invoke the method sign on the token. The default value is
                // SHA256
                if (signatureAlgorithm != null) {
                    xAdESSigParameters.setDigestAlgorithm(signatureAlgorithm.getDigestAlgorithm());
                    xAdESSigParameters.setEncryptionAlgorithm(signatureAlgorithm.getEncryptionAlgorithm());
                    xAdESSigParameters.setMaskGenerationFunction(signatureAlgorithm.getMaskGenerationFunction());
                } else if (digestAlgorithm != null) {
                    xAdESSigParameters.setDigestAlgorithm(digestAlgorithm);
                }
                // We set the signing certificate
                xAdESSigParameters.setSigningCertificate(signingCertificate);
                // We set the certificate chain
                xAdESSigParameters.setCertificateChain(certificateTokens);
                //
                if (TIMESTAMPING_REQUIRED.contains(adESSignatureLevel)) {
                    xAdESSigParameters.setContentTimestampParameters(new XAdESTimestampParameters(tsaDigestAlgorithm));
                }
                if (addContentTimestamp) {
                    xAdESSigParameters.setContentTimestamps(contentTimestamps);
                }
                this.xAdESSignatureParameters = xAdESSigParameters;
                break;
            default:
                // this shouldn't really happen...
                throw new IllegalArgumentException("Unknown signature format: " + adESSignatureFormat);
        }
        return this;
    }

    public PAdESSignatureParameters getPAdESSignatureParameters() {
        Objects.requireNonNull(pAdESSignatureParameters,
                "Improper usage of AdESSignatureParameters for PAdESSignatureParameters, build it first.");
        return pAdESSignatureParameters;
    }

    public XAdESSignatureParameters getXAdESSignatureParameters() {
        Objects.requireNonNull(xAdESSignatureParameters,
                "Improper usage of AdESSignatureParameters for XAdESSignatureParameters, build it first.");
        return xAdESSignatureParameters;
    }

    /**
     * Gets the DSS SignatureLevel value corresponding to the configured
     * signature level of the signer.
     *
     * @return DSS SignatureLevel corresponding to the configured properties
     */
    private SignatureLevel getSignatureLevel() {
        switch (adESSignatureLevel) {
            case BASELINE_B:
                switch (adESSignatureFormat) {
                    case PAdES:
                        return SignatureLevel.PAdES_BASELINE_B;
                    case XAdES:
                        return SignatureLevel.XAdES_BASELINE_B;
                    default:
                        throw new IllegalArgumentException("Unknown signature format: " + adESSignatureFormat);
                }
            case BASELINE_T:
                switch (adESSignatureFormat) {
                    case PAdES:
                        return SignatureLevel.PAdES_BASELINE_T;
                    case XAdES:
                        return SignatureLevel.XAdES_BASELINE_T;
                    default:
                        throw new IllegalArgumentException("Unknown signature format: " + adESSignatureFormat);
                }
            case BASELINE_LT:
                switch (adESSignatureFormat) {
                    case PAdES:
                        return SignatureLevel.PAdES_BASELINE_LT;
                    case XAdES:
                        return SignatureLevel.XAdES_BASELINE_LT;
                    default:
                        throw new IllegalArgumentException("Unknown signature format: " + adESSignatureFormat);
                }
            case BASELINE_LTA:
                switch (adESSignatureFormat) {
                    case PAdES:
                        return SignatureLevel.PAdES_BASELINE_LTA;
                    case XAdES:
                        return SignatureLevel.XAdES_BASELINE_LTA;
                    default:
                        throw new IllegalArgumentException("Unknown signature format: " + adESSignatureFormat);
                }
            default:
                // this shouldn't really happen...
                throw new IllegalArgumentException("Unknown signature level: " + adESSignatureLevel);
        }
    }
}
