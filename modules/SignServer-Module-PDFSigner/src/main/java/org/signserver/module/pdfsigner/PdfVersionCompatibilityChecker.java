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
package org.signserver.module.pdfsigner;

/**
 * Class checking compatibility of PDF version against signature digest algorithm.
 * 
 * @author Aziz Göktepe
 * @version $Id$
 */
public class PdfVersionCompatibilityChecker {

    private int pdfVersionOfDocumentToBeSigned;
    private final String signatureDigestAlgorithm;

    public PdfVersionCompatibilityChecker(String pPdfVersionOfDocumentToBeSigned, String pSignatureDigestAlgorithm) {
        try {
            pdfVersionOfDocumentToBeSigned = Integer.parseInt(pPdfVersionOfDocumentToBeSigned);
        } catch (NumberFormatException e) {
            pdfVersionOfDocumentToBeSigned = 0;
        }

        signatureDigestAlgorithm = pSignatureDigestAlgorithm;
    }
    
    /**
     * @return PDF version of document to be signed
     */
    public int getPdfVersionOfDocumentToBeSigned() {
        return pdfVersionOfDocumentToBeSigned;
    }

    /**
     * Tests if PDF version upgrade is required to sign using given digest algorithm.
     * 
     * @return true if PDF version upgrade is required, false otherwise
     */
    public boolean isVersionUpgradeRequired() {
        return pdfVersionOfDocumentToBeSigned < getMinimumCompatiblePdfVersion();
    }

    /**
     * Gets minimum required PDF Version to be able to sign document using given digest algorithm. 
     * 
     * @return minimum PDF version number required
     */
    public int getMinimumCompatiblePdfVersion() {
        switch (signatureDigestAlgorithm) {
            case PdfSignatureDigestAlgorithms.SHA1:
                return 0;
            case PdfSignatureDigestAlgorithms.SHA256:
            case PdfSignatureDigestAlgorithms.SHA_256:
                return 6;
            case PdfSignatureDigestAlgorithms.SHA384:
            case PdfSignatureDigestAlgorithms.SHA_384:
            case PdfSignatureDigestAlgorithms.SHA512:
            case PdfSignatureDigestAlgorithms.SHA_512:
            case PdfSignatureDigestAlgorithms.RIPEMD160:
                return 7;
            default:
                throw new IllegalArgumentException("Unknown digest algorithm: " + signatureDigestAlgorithm);
        }
    }

}
