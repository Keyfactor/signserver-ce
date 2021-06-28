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

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.signserver.common.SignServerUtil;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertEquals;

/**
 * Unit tests for the AdESService class.
 *
 * @author Andrey Sergeev
 * @version $Id$
 */
public class AdESSignatureParametersUnitTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    public static KeyPair KEY_PAIR_RSA;
    public static List<CertificateToken> CERTIFICATE_CHAIN;
    public static CertificateToken CERTIFICATE;

    @BeforeClass
    public static void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        KEY_PAIR_RSA = CryptoUtils.generateRSA(1024);
        final X509Certificate x509Certificate = new JcaX509CertificateConverter()
                .getCertificate(
                        new CertBuilder()
                                .setSelfSignKeyPair(KEY_PAIR_RSA)
                                .setNotBefore(new Date())
                                .setSignatureAlgorithm("SHA256withRSA")
                                .build()
                );
        CERTIFICATE = new CertificateToken(x509Certificate);CERTIFICATE = new CertificateToken(x509Certificate);
        CERTIFICATE_CHAIN = Collections.singletonList(new CertificateToken(x509Certificate));
    }

    @Test
    public void shouldBuildCorrespondingPAdESSignatureParameters() {
        // given
        final SignatureAlgorithm expectedSignatureAlgorithm = SignatureAlgorithm.RSA_SHA3_224;
        final DigestAlgorithm expectedDigestAlgorithm = DigestAlgorithm.SHA3_224;
        final boolean expectedAddContentTimestamp = true;
        final DigestAlgorithm expectedTSADigestAlgorithm = DigestAlgorithm.MD5;
        // when
        final AdESSignatureParameters parameters = AdESSignatureParameters.builder()
                .withAdESSignatureLevel(AdESSignatureLevel.BASELINE_B)
                .withAdESSignatureFormat(AdESSignatureFormat.PAdES)
                .withSignatureAlgorithm(expectedSignatureAlgorithm)
                .withDigestAlgorithm(expectedDigestAlgorithm)
                .withSigningCertificate(CERTIFICATE)
                .withCertificateChain(CERTIFICATE_CHAIN)
                .withAddContentTimestamp(expectedAddContentTimestamp)
                .withTSADigestAlgorithm(expectedTSADigestAlgorithm)
                .build();
        final PAdESSignatureParameters pAdESSignatureParameters = parameters.getPAdESSignatureParameters();
        // then
        assertNotNull("PAdESSignatureParameters should be not null.", pAdESSignatureParameters);
        assertEquals("PAdESSignatureParameters - SignatureAlgorithm.", expectedSignatureAlgorithm, pAdESSignatureParameters.getSignatureAlgorithm());
        assertEquals("PAdESSignatureParameters - DigestAlgorithm.", expectedDigestAlgorithm, pAdESSignatureParameters.getDigestAlgorithm());
        assertEquals("PAdESSignatureParameters - SigningCertificate.", CERTIFICATE, pAdESSignatureParameters.getSigningCertificate());
        assertEquals("PAdESSignatureParameters - CertificateChain.", CERTIFICATE_CHAIN, pAdESSignatureParameters.getCertificateChain());

    }

}
