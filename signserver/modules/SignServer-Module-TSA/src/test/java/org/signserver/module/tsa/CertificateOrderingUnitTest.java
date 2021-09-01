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

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.cesecore.util.CertTools;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.data.SignatureRequest;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.server.IServices;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.log.AdminInfo;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.MockedRequestContext;
import org.signserver.test.utils.mock.MockedServicesImpl;
import org.signserver.test.utils.mock.WorkerSessionMock;
import org.signserver.testutils.ModulesTestCase;

import static org.junit.Assert.assertEquals;

/**
 * Unit tests for the encoding of the time-stamp tokens and specifically related to the ordering of the certificates in the output.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CertificateOrderingUnitTest extends ModulesTestCase {

    private static final int WORKER1 = 8890;
    private static final String NAME = "NAME";
    private static final String AUTHTYPE = "AUTHTYPE";
    private static final String CRYPTOTOKEN_CLASSNAME =
            "org.signserver.server.cryptotokens.KeystoreCryptoToken";

    private static final String KEY_ALIAS = "ts00001";

    private WorkerSessionLocal workerSession;
    private WorkerSessionMock processSession;
    private IServices services;
    private WorkerSessionMock workerMock;

    private X509Certificate cert100;
    private X509Certificate cert101;
    private X509Certificate cert102;
    private X509Certificate cert103;

    @Before
    public void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        final GlobalConfigurationSessionMock globalMock
                = new GlobalConfigurationSessionMock();
        workerMock = new WorkerSessionMock();
        workerSession = workerMock;
        processSession = workerMock;
        services = new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, globalMock);

        cert100 = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSerialNumber(new BigInteger("100")).setSubject("CN=Cert 100").addExtension(new CertExt(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping))).build());
        cert101 = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSerialNumber(new BigInteger("101")).setSubject("CN=Cert 101").build());
        cert102 = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSerialNumber(new BigInteger("102")).setSubject("CN=Cert 102").build());
        cert103 = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSerialNumber(new BigInteger("103")).setSubject("CN=Cert 103").build());
    }

    private String createPem(List<? extends Certificate> certs) throws CertificateEncodingException {
        return new String(CertTools.getPemFromCertificateChain((List<Certificate>)certs), StandardCharsets.US_ASCII);
    }

    private byte[] timestamp(TimeStampRequest timeStampRequest, int workerId) throws Exception {
        byte[] requestBytes = timeStampRequest.getEncoded();
        try (
                CloseableReadableData requestData = createRequestData(requestBytes);
                CloseableWritableData responseData = createResponseData(false)
            ) {
            SignatureRequest signRequest = new SignatureRequest(100, requestData, responseData);

            processSession.process(new AdminInfo("Client user", null, null), new WorkerIdentifier(workerId), signRequest, new MockedRequestContext(services));

            return responseData.toReadableData().getAsByteArray();
        }
    }

    private TimeStampResponse getTimeStampResponse(byte[] data) throws TSPException, IOException {
        return new TimeStampResponse(data);
    }

    private List<X509CertificateHolder> timestampWithCerts(X509Certificate cert, List<X509Certificate> certs, boolean normalMode) throws Exception {
        final int workerId = WORKER1;
        final WorkerConfig config = new WorkerConfig();
        config.setProperty(NAME, "TestTimeStampSigner1");
        config.setProperty(AUTHTYPE, "NOAUTH");
        config.setProperty(TimeStampSigner.DEFAULTTSAPOLICYOID,
                           "1.3.6.1.4.1.22408.1.2.3.45");
        config.setProperty("DEFAULTKEY", KEY_ALIAS);
        config.setProperty("KEYSTOREPATH",
            getSignServerHome() + File.separator + "res" +
                    File.separator + "test" + File.separator + "dss10" +
                    File.separator + "dss10_keystore.p12");
        config.setProperty("KEYSTORETYPE", "PKCS12");
        config.setProperty("KEYSTOREPASSWORD", "foo123");
        config.setProperty("ACCEPTANYPOLICY", "true");

        config.setProperty("SIGNERCERT", createPem(Collections.singletonList(cert)));
        config.setProperty("SIGNERCERTCHAIN", createPem(certs));
        config.setProperty("LEGACYENCODING", Boolean.toString(!normalMode));
        // Don't verify timestamp token signature in this test as it uses certificate in configuration which is not associated with the signing key
        config.setProperty("VERIFY_TOKEN_SIGNATURE", "false");

        workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                new TimeStampSigner());
        workerSession.reloadConfiguration(workerId);

        TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
        timeStampRequestGenerator.setCertReq(true);
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = getTimeStampResponse(timestamp(timeStampRequest, WORKER1));
        timeStampResponse.validate(timeStampRequest);

        System.out.println(timeStampResponse.getStatusString());
        TimeStampToken token = timeStampResponse.getTimeStampToken();
        Store store = token.getCertificates();
        System.out.println("certs: " + store);
        System.out.println("time: " + token.getTimeStampInfo().getGenTime());

        return (List<X509CertificateHolder>) token.getCertificates().getMatches(new AllSelector());
    }

    private String toStringJce(List<X509Certificate> certs) {
        ArrayList<String> certSerials = new ArrayList<>();
        for (X509Certificate c : certs) {
            certSerials.add(c.getSerialNumber().toString());
        }
        return certSerials.toString();
    }

    private String toStringBc(List<X509CertificateHolder> certs) {
        ArrayList<String> actualCertSerials = new ArrayList<>();
        for (X509CertificateHolder c : certs) {
            actualCertSerials.add(c.getSerialNumber().toString());
        }
        return actualCertSerials.toString();
    }

    /**
     * Tests time-stamping in normal mode (i.e. not using "legacy mode") and checks that the order is not the same in the output as it were in
     * the input.
     */
    @Test
    public void testNormalMode() throws Exception {
        X509Certificate cert = cert100;
        List<X509Certificate> certs = Arrays.asList(cert100, cert101, cert102, cert103);
        final List<X509Certificate> expected = Arrays.asList(cert101, cert102, cert103, cert100); // We expect this different order

        List<X509CertificateHolder> actualCerts = timestampWithCerts(cert, certs, true);
        assertEquals(toStringJce(expected), toStringBc(actualCerts));

        certs = Arrays.asList(cert103, cert100, cert102, cert101); // With a different order we still expect the same
        actualCerts = timestampWithCerts(cert, certs, true);
        assertEquals(toStringJce(expected), toStringBc(actualCerts));

        certs = Arrays.asList(cert102, cert103, cert101, cert100); // With a different order we still expect the same
        actualCerts = timestampWithCerts(cert, certs, true);
        assertEquals(toStringJce(expected), toStringBc(actualCerts));
    }

    /**
     * Tests time-stamping in "legacy mode" and checks that the order is the same in the output as it were in
     * the input.
     */
    @Test
    public void testLegacyMode() throws Exception {
        X509Certificate cert = cert100;
        List<X509Certificate> certs = Arrays.asList(cert100, cert101, cert102, cert103);
        List<X509Certificate> expected = certs; // Same order

        List<X509CertificateHolder> actualCerts = timestampWithCerts(cert, certs, false);
        assertEquals(toStringJce(expected), toStringBc(actualCerts));

        certs = Arrays.asList(cert103, cert100, cert102, cert101);
        expected = certs; // Same order
        actualCerts = timestampWithCerts(cert, certs, false);
        assertEquals(toStringJce(expected), toStringBc(actualCerts));

        certs = Arrays.asList(cert102, cert103, cert101, cert100);
        expected = certs; // Same order
        actualCerts = timestampWithCerts(cert, certs, false);
        assertEquals(toStringJce(expected), toStringBc(actualCerts));
    }

    /**
     * Simply matches true on all objects found.
     */
    public static class AllSelector implements Selector {
        @Override
        public boolean match(Object obj) {
            return true;
        }

        @Override
        @SuppressWarnings({"CloneDoesntCallSuperClone", "CloneDeclaresCloneNotSupported"})
        public Object clone() {
            return new AllSelector();
        }
    }

}
