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
package org.signserver.module.tsa;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Optional;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.data.SignatureRequest;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.module.tsa.conf.TSAWorkerConfigBuilder;
import org.signserver.server.IServices;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.log.AdminInfo;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.MockedRequestContext;
import org.signserver.test.utils.mock.MockedServicesImpl;
import org.signserver.test.utils.mock.WorkerSessionMock;
import org.signserver.testutils.ModulesTestCase;

import static org.junit.Assert.assertEquals;
import org.signserver.common.SignServerException;
import org.signserver.server.cesecore.certificates.util.AlgorithmConstants;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.cryptotokens.NullCryptoToken;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.test.utils.mock.MockedCryptoToken;

/**
 * Unit tests for the TimeStampSigner using composites.
 */
public class CompositeTimeStampSignerUnitTest extends ModulesTestCase {

    private static final Logger LOG = Logger.getLogger(CompositeTimeStampSignerUnitTest.class);

    private static final int WORKER1 = 18890;

    // OID description: we sign anything that arrives
    private static final String DEFAULT_TSA_POLICY_OID = "1.3.6.1.4.1.22408.1.2.3.45";
    private static MockedCryptoToken tokenComposite;
    private static String signatureAlgorithm;

    private WorkerSessionLocal workerSession;
    private WorkerSessionMock processSession;
    private IServices services;

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Create a (native) composite key-pair, issue a (self-signed) time-stamping certificate
        {
            ASN1ObjectIdentifier compositeOID = IANAObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512;
            signatureAlgorithm = AlgorithmConstants.SIGALG_MLDSA87_RSA3072_PSS_SHA512;
            
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(compositeOID.getId(), "BC");
            KeyPair compKeyPair = keyPairGenerator.generateKeyPair();
            PublicKey compPublicKey = compKeyPair.getPublic();
            PrivateKey compPrivateKey = compKeyPair.getPrivate();
            
            X509CertificateHolder certHolder = new CertBuilder()
                    .setSelfSignKeyPair(new KeyPair(compPublicKey, compPrivateKey))
                    .setNotBefore(new Date())
                    .setSignatureAlgorithm(signatureAlgorithm)
                    .addExtension(new CertExt(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping)))
                    .build();
            final Certificate[] certChain =
                    new Certificate[]{new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder)};
            final Certificate signerCertificate = certChain[0];
            tokenComposite = new MockedCryptoToken(compPrivateKey, compPublicKey, signerCertificate, Arrays.asList(certChain), "BC");
        }
    }

    @Before
    public void setUp() throws Exception {
        setupWorkers();
    }

    private void setupWorkers() throws Exception {
        final WorkerSessionMock workerMock = new WorkerSessionMock();
        workerSession = workerMock;
        processSession = workerMock;
        services = new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, new GlobalConfigurationSessionMock());

        // WORKER1
        {
            final WorkerConfig config = TSAWorkerConfigBuilder.builder()
                    .withWorkerId(WORKER1)
                    .withWorkerName("TestTimeStampSigner1")
                    .withNoAuthAuthType()
                    .withDefaultTsaPolicyOid(DEFAULT_TSA_POLICY_OID)
                    .withDss10p12Keystore()
                    .withAcceptAnyPolicy(true)
                    .build();
            config.setProperty("SIGNATUREALGORITHM", signatureAlgorithm);

            workerMock.setupWorker(WORKER1, NullCryptoToken.class.getName(), config,
                    new TimeStampSigner() {
                        @Override
                        public ICryptoTokenV4 getCryptoToken(IServices services) throws SignServerException {
                            return tokenComposite;
                        }
                    });
            workerSession.reloadConfiguration(WORKER1);
        }
    }

    /**
     * Tests time-stamping using a native composite (soft/BC) key and certificate.
     * @throws Exception in case of error
     */
    @Test
    public void testTimeStamp_NativeComposite() throws Exception {
        LOG.info("testTimeStamp_NativeComposite");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.setCertReq(true);
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER1);
        timeStampResponse.validate(timeStampRequest);
        assertEquals("granted", PKIStatus.GRANTED, timeStampResponse.getStatus());
        
        X509Certificate certificate = (X509Certificate) tokenComposite.getCertificate(0);

        SignerInformationVerifier infoVerifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificate);
        timeStampResponse.getTimeStampToken().validate(infoVerifier);
    }
    
    /**
     * Tests that time-stamping can be done without setting SIGNATUREALGORITHM,
     * i.e. there is a default value.
     * @throws Exception in case of error
     */
    @Test
    public void testTimeStamp_compositeWithoutSignatureAlgorithm() throws Exception {
        LOG.info("testTimeStamp_compositeWithoutSignatureAlgorithm");
        
        // Remove the signature algorithm
        workerSession.removeWorkerProperty(null, WORKER1, "SIGNATUREALGORITHM");
        workerSession.reloadConfiguration(WORKER1);

        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.setCertReq(true);
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER1);
        timeStampResponse.validate(timeStampRequest);
        assertEquals("granted", PKIStatus.GRANTED, timeStampResponse.getStatus());
        
        X509Certificate certificate = (X509Certificate) tokenComposite.getCertificate(0);

        SignerInformationVerifier infoVerifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificate);
        timeStampResponse.getTimeStampToken().validate(infoVerifier);
    }

    private TimeStampResponse timestamp(TimeStampRequest timeStampRequest, int workerId) throws Exception {
        byte[] requestBytes = timeStampRequest.getEncoded();
        try (
                CloseableReadableData requestData = createRequestData(requestBytes);
                CloseableWritableData responseData = createResponseData(false)
            ) {
            SignatureRequest signRequest = new SignatureRequest(100, requestData, responseData);

            processSession.process(new AdminInfo("Client user", null, null), new WorkerIdentifier(workerId),
                    Optional.empty(), Optional.empty(), signRequest, new MockedRequestContext(services));

            return new TimeStampResponse(responseData.toReadableData().getAsInputStream());
        }
    }

}
