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

import java.util.Objects;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

/**
 * A delegate-proxy class to combine PAdESService and XAdESService.
 *
 * @author Andrey Sergeev
 * @version $Id: AdESSignatureFormat.java 12692 2021-05-25 07:32:07Z malu9369 $
 */
public class AdESService {

    private final AdESSignatureFormat adESSignatureFormat;
    //
    private PAdESService pAdESService;
    private XAdESService xAdESService;

    /**
     * Constructor.
     * @param adESSignatureFormat AdES signature format.
     * @param certificateVerifier Certificate verifier.
     * @see PAdESService(CertificateVerifier)
     * @see XAdESService(CertificateVerifier)
     */
    public AdESService(final AdESSignatureFormat adESSignatureFormat, final CertificateVerifier certificateVerifier) {
        Objects.requireNonNull(adESSignatureFormat, "AdESSignatureFormat is required.");
        this.adESSignatureFormat = adESSignatureFormat;
        switch (adESSignatureFormat) {
            case PAdES:
                pAdESService = new PAdESService(certificateVerifier);
                break;
            case XAdES:
                xAdESService = new XAdESService(certificateVerifier);
                break;
            default:
                // this shouldn't really happen...
                throw new IllegalArgumentException("Unknown signature format: " + adESSignatureFormat);
        }
    }

    /**
     * Sets the TSP source to use for timestamp requests.
     * @param tspSource the TSP source to use for timestamp requests.
     * @see PAdESService#setTspSource(TSPSource)
     * @see XAdESService#setTspSource(TSPSource)
     */
    public void setTspSource(final TSPSource tspSource) {
        switch (adESSignatureFormat) {
            case PAdES:
                pAdESService.setTspSource(tspSource);
                break;
            case XAdES:
                xAdESService.setTspSource(tspSource);
                break;
            // this shouldn't really happen...
            default:
                throw new IllegalArgumentException("Unknown signature format: " + adESSignatureFormat);
        }
    }

    /**
     * Computes a content-timestamp.
     * @param toSignDocument document to sign or the already existing signature.
     * @param parameters AdES signature parameters.
     * @return computed content-timestamp.
     * @see PAdESService#getContentTimestamp(DSSDocument, PAdESSignatureParameters)
     * @see XAdESService#getContentTimestamp(DSSDocument, XAdESSignatureParameters)
     */
    public TimestampToken getContentTimestamp(final DSSDocument toSignDocument, final AdESSignatureParameters parameters) {
        switch (adESSignatureFormat) {
            case PAdES:
                return pAdESService.getContentTimestamp(toSignDocument, parameters.getPAdESSignatureParameters());
            case XAdES:
                return xAdESService.getContentTimestamp(toSignDocument, parameters.getXAdESSignatureParameters());
            // this shouldn't really happen...
            default:
                throw new IllegalArgumentException("Unknown signature format: " + adESSignatureFormat);
        }
    }

    /**
     * Retrieves the bytes of the data that need to be signed based on the toSignDocument and parameters.
     * @param toSignDocument document to sign or the already existing signature.
     * @param parameters AdES signature parameters.
     * @return the bytes of the data for signing.
     * @see PAdESService#getDataToSign(DSSDocument, PAdESSignatureParameters)
     * @see XAdESService#getDataToSign(DSSDocument, XAdESSignatureParameters)
     */
    public ToBeSigned getDataToSign(final DSSDocument toSignDocument, final AdESSignatureParameters parameters) {
        switch (adESSignatureFormat) {
            case PAdES:
                return pAdESService.getDataToSign(toSignDocument, parameters.getPAdESSignatureParameters());
            case XAdES:
                return xAdESService.getDataToSign(toSignDocument, parameters.getXAdESSignatureParameters());
            // this shouldn't really happen...
            default:
                throw new IllegalArgumentException("Unknown signature format: " + adESSignatureFormat);
        }
    }

    /**
     * Verifies the signature value against a ToBeSigned and a CertificateToken.
     * @param toBeSigned the signed data.
     * @param signatureValue the signature value.
     * @param signingCertificate the used certificate to create the signature value.
     * @return true if the signature value is valid.
     * @see PAdESService#isValidSignatureValue(ToBeSigned, SignatureValue, CertificateToken)
     * @see XAdESService#isValidSignatureValue(ToBeSigned, SignatureValue, CertificateToken)
     */
    public boolean isValidSignatureValue(final ToBeSigned toBeSigned, final SignatureValue signatureValue, final CertificateToken signingCertificate) {
        switch (adESSignatureFormat) {
            case PAdES:
                return pAdESService.isValidSignatureValue(toBeSigned, signatureValue, signingCertificate);
            case XAdES:
                return xAdESService.isValidSignatureValue(toBeSigned, signatureValue, signingCertificate);
            // this shouldn't really happen...
            default:
                throw new IllegalArgumentException("Unknown signature format: " + adESSignatureFormat);
        }
    }

    /**
     * Signs the toSignDocument with the provided signatureValue.
     * @param toSignDocument document to sign.
     * @param parameters AdES signature parameters.
     * @param signatureValue the signature value.
     * @return the signed document.
     * @see PAdESService#signDocument(DSSDocument, PAdESSignatureParameters, SignatureValue)
     * @see XAdESService#signDocument(DSSDocument, XAdESSignatureParameters, SignatureValue)
     */
    public DSSDocument signDocument(final DSSDocument toSignDocument, final AdESSignatureParameters parameters, final SignatureValue signatureValue) {
        switch (adESSignatureFormat) {
            case PAdES:
                return pAdESService.signDocument(toSignDocument, parameters.getPAdESSignatureParameters(), signatureValue);
            case XAdES:
                return xAdESService.signDocument(toSignDocument, parameters.getXAdESSignatureParameters(), signatureValue);
            // this shouldn't really happen...
            default:
                throw new IllegalArgumentException("Unknown signature format: " + adESSignatureFormat);
        }
    }
}
