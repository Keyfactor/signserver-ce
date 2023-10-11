package org.signserver.server;

import java.security.cert.Certificate;

/**
 * Utility class that helps with renewal of worker certificate.
 */
public class RenewalUtils {

    /** Constant for the SIGNATUREALGORITHM property. */
    public static final String PROPERTY_SIGNATUREALGORITHM = "SIGNATUREALGORITHM";

    /** Constant for the optional REQUESTSIGNATUREALGORITHM property. */
    public static final String PROPERTY_REQUESTSIGNATUREALGORITHM = "REQUESTSIGNATUREALGORITHM";

    private RenewalUtils() {}

    /**
     * Returns a valid and relevant signature algorithm based on input.
     * @param requestSignatureAlgorithm algorithm specified to use for the request or an empty string if not available
     * @param signatureAlgorithm signatureAlgorithm algorithm used by the signer
     * @param signerCert signerCert certificate used by the signer or null if not available
     * @return a valid and relevant signature algorithm, if none could be found it will default to SHA512withRSA.
     */
    public static String getRequestSignatureAlgorithm(String requestSignatureAlgorithm, String signatureAlgorithm, Certificate signerCert) {
        String ret;
        if (requestSignatureAlgorithm.trim().isEmpty()) {
            if (!signatureAlgorithm.startsWith("NONEwith") && !signatureAlgorithm.trim().isEmpty()) {
                ret = signatureAlgorithm;
            } else if (signerCert != null) {
                final String keyAlg = "EC".equalsIgnoreCase(signerCert.getPublicKey().getAlgorithm()) ? "ECDSA" : signerCert.getPublicKey().getAlgorithm();
                ret = keyAlg.startsWith("Ed") ? keyAlg : "SHA512with" + keyAlg;
            } else {
                ret = "SHA512withRSA";
            }
        } else {
            ret = requestSignatureAlgorithm;
        }
        return ret;
    }

}
