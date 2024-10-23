/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.server.cesecore.certificates.util;

import java.util.Arrays;
import java.util.List;

/** Constants for digital signature algorithms.
 * NOTE: THIS IS A COPY FROM org.cesecore.certificates.util
 * THIS CLASS WILL BE REMOVED WHEN UPGRADING CESECORE (DSS-2129)
 */
public final class AlgorithmConstants {

    public static final String SIGALG_MD5_WITH_RSA             = "MD5WithRSA";
    public static final String SIGALG_SHA1_WITH_RSA            = "SHA1WithRSA";
    public static final String SIGALG_SHA256_WITH_RSA          = "SHA256WithRSA";
    public static final String SIGALG_SHA384_WITH_RSA          = "SHA384WithRSA";
    public static final String SIGALG_SHA512_WITH_RSA          = "SHA512WithRSA";
    public static final String SIGALG_SHA3_256_WITH_RSA        = "SHA3-256withRSA";
    public static final String SIGALG_SHA3_384_WITH_RSA        = "SHA3-384withRSA";
    public static final String SIGALG_SHA3_512_WITH_RSA        = "SHA3-512withRSA";
    public static final String SIGALG_SHA1_WITH_ECDSA          = "SHA1withECDSA";
    public static final String SIGALG_SHA224_WITH_ECDSA        = "SHA224withECDSA";
    public static final String SIGALG_SHA256_WITH_ECDSA        = "SHA256withECDSA";
    public static final String SIGALG_SHA384_WITH_ECDSA        = "SHA384withECDSA";
    public static final String SIGALG_SHA512_WITH_ECDSA        = "SHA512withECDSA";
    public static final String SIGALG_SHA3_256_WITH_ECDSA      = "SHA3-256withECDSA";
    public static final String SIGALG_SHA3_384_WITH_ECDSA      = "SHA3-384withECDSA";
    public static final String SIGALG_SHA3_512_WITH_ECDSA      = "SHA3-512withECDSA";
    public static final String SIGALG_SHA256_WITH_RSA_AND_MGF1 = "SHA256withRSAandMGF1";
    public static final String SIGALG_SHA384_WITH_RSA_AND_MGF1 = "SHA384withRSAandMGF1";
    public static final String SIGALG_SHA512_WITH_RSA_AND_MGF1 = "SHA512withRSAandMGF1";
    public static final String SIGALG_SHA1_WITH_RSA_AND_MGF1 = "SHA1withRSAandMGF1";
    public static final String SIGALG_GOST3411_WITH_ECGOST3410 = "GOST3411withECGOST3410";
    public static final String SIGALG_GOST3411_WITH_DSTU4145   = "GOST3411withDSTU4145";
    public static final String SIGALG_ED25519                  = "Ed25519";
    public static final String SIGALG_ED448                    = "Ed448";
    public static final String SIGALG_MLDSA                    = "ML-DSA";
    public static final String SIGALG_MLDSA44                  = "ML-DSA-44";
    public static final String SIGALG_MLDSA65                  = "ML-DSA-65";
    public static final String SIGALG_MLDSA87                  = "ML-DSA-87";
    public static final String SIGALG_LMS                      = "LMS";
    public static final String SIGALG_SLHDSA_SHA2_128F         = "slh-dsa-sha2-128f";
    public static final String SIGALG_SLHDSA_SHA2_128S         = "slh-dsa-sha2-128s";
    public static final String SIGALG_SLHDSA_SHA2_192F         = "slh-dsa-sha2-192f";
    public static final String SIGALG_SLHDSA_SHA2_192S         = "slh-dsa-sha2-192s";
    public static final String SIGALG_SLHDSA_SHA2_256F         = "slh-dsa-sha2-256f";
    public static final String SIGALG_SLHDSA_SHA2_256S         = "slh-dsa-sha2-256s";
    public static final String SIGALG_SLHDSA_SHAKE_128F        = "slh-dsa-shake-128f";
    public static final String SIGALG_SLHDSA_SHAKE_128S        = "slh-dsa-shake-128s";
    public static final String SIGALG_SLHDSA_SHAKE_192F        = "slh-dsa-shake-192f";
    public static final String SIGALG_SLHDSA_SHAKE_192S        = "slh-dsa-shake-192s";
    public static final String SIGALG_SLHDSA_SHAKE_256F        = "slh-dsa-shake-256f";
    public static final String SIGALG_SLHDSA_SHAKE_256S        = "slh-dsa-shake-256s";


    /**
     * Signature algorithms available to choose from.
     * Call AlgorithmTools.isSigAlgEnabled() to determine if a given sigalg is enabled and should be shown in the UI.
     */
    public static final String[] AVAILABLE_SIGALGS = {
            SIGALG_SHA1_WITH_RSA,
            SIGALG_SHA256_WITH_RSA,
            SIGALG_SHA384_WITH_RSA,
            SIGALG_SHA512_WITH_RSA,
            SIGALG_SHA3_256_WITH_RSA,
            SIGALG_SHA3_384_WITH_RSA,
            SIGALG_SHA3_512_WITH_RSA,
            SIGALG_SHA256_WITH_RSA_AND_MGF1,
            SIGALG_SHA384_WITH_RSA_AND_MGF1,
            SIGALG_SHA512_WITH_RSA_AND_MGF1,
            SIGALG_SHA1_WITH_ECDSA,
            SIGALG_SHA224_WITH_ECDSA,
            SIGALG_SHA256_WITH_ECDSA,
            SIGALG_SHA384_WITH_ECDSA,
            SIGALG_SHA512_WITH_ECDSA,
            SIGALG_SHA3_256_WITH_ECDSA,
            SIGALG_SHA3_384_WITH_ECDSA,
            SIGALG_SHA3_512_WITH_ECDSA,
            SIGALG_GOST3411_WITH_ECGOST3410,           
            SIGALG_GOST3411_WITH_DSTU4145,
            SIGALG_ED25519,
            SIGALG_ED448,
            SIGALG_MLDSA,
            SIGALG_MLDSA44,
            SIGALG_MLDSA65,
            SIGALG_MLDSA87,
            SIGALG_LMS,
            SIGALG_SLHDSA_SHA2_128F,
            SIGALG_SLHDSA_SHA2_128S,
            SIGALG_SLHDSA_SHA2_192F,
            SIGALG_SLHDSA_SHA2_192S,
            SIGALG_SLHDSA_SHA2_256F,
            SIGALG_SLHDSA_SHA2_256S,
            SIGALG_SLHDSA_SHAKE_128F,
            SIGALG_SLHDSA_SHAKE_128S,
            SIGALG_SLHDSA_SHAKE_192F,
            SIGALG_SLHDSA_SHAKE_192S,
            SIGALG_SLHDSA_SHAKE_256F,
            SIGALG_SLHDSA_SHAKE_256S
    };

    public static final String KEYALGORITHM_RSA         = "RSA";
    public static final String KEYALGORITHM_EC          = "EC";
    public static final String KEYALGORITHM_ECDSA       = "ECDSA"; //The same as "EC", just named differently sometimes. "EC" and "ECDSA" should be handled in the same way
    public static final String KEYALGORITHM_ECGOST3410  = "ECGOST3410";
    public static final String KEYALGORITHM_DSTU4145    = "DSTU4145";
    public static final String KEYALGORITHM_EDDSA       = "EdDSA";
    public static final String KEYALGORITHM_MLDSA       = "ML-DSA";
    public static final String KEYALGORITHM_LMS         = "LMS";
    public static final String KEYALGORITHM_SLHDSA      = "SLH-DSA";

    public static final String KEYSPECPREFIX_ECGOST3410 = "GostR3410-";

    public static final List<String> BLACKLISTED_EC_CURVES = Arrays.asList(new String[]{
            // No blacklisted EC curves at the moment
    });

    // Extra EC curves that we want to include that are not part of the "standard" curves in BC (ECNamedCurveTable.getNames)
    public static final List<String> EXTRA_EC_CURVES = Arrays.asList(new String[]{
            // Part of CustomNamedCurves in BouncyCastle 1.54
            // Commented out due to experimental nature 2017-04 as the signatures using this currently probably is not correct
            // Should probably wait for edDSA, See ECA-5796 and linked issues.
            //"curve25519",
    });

    private AlgorithmConstants () {} // Not for instantiation
}
