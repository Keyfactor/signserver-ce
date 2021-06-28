/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.ades.signer;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.ListRevocationSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.junit.Test;
import org.signserver.common.*;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.ProcessSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.module.ades.AdESSignatureFormat;
import org.signserver.module.ades.AdESSignatureLevel;
import org.signserver.module.ades.conf.AdESWorkerConfigBuilder;
import org.signserver.server.IServices;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.test.conf.WorkerConfigBuilder;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertBuilderException;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.test.utils.mock.MockedServicesImpl;
import org.signserver.test.utils.mock.WorkerSessionMock;
import org.signserver.testutils.ModulesTestCase;
import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.module.tsa.TimeStampSigner;
import org.signserver.server.cesecore.util.CertTools;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.test.utils.builders.crl.CRLBuilder;
import org.signserver.test.utils.builders.ocsp.OCSPResponse;
import org.signserver.test.utils.builders.ocsp.OCSPResponseBuilder;
import org.signserver.test.utils.builders.ocsp.OCSPResponseBuilderException;
import org.signserver.test.utils.builders.ocsp.OcspRespObject;

/**
 * Unit tests for the AdESSigner class.
 *
 * @author Nima Saboonchi
 * @version $Id: AdESSignerUnitTest.java 11795 2020-01-29 15:28:36Z $
 */
public class AdESSignerUnitTest extends ModulesTestCase {

    private static final Logger LOG = Logger.getLogger(AdESSignerUnitTest.class);

    private WorkerSessionLocal workerSession;
    private ProcessSessionLocal processSession;
    private static final String CRYPTOTOKEN_CLASSNAME =
            "org.signserver.server.cryptotokens.KeystoreCryptoToken";
    private final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

    /** Crypto Provider */
    private static final String PROVIDER = "BC";

    /** Worker/Signer ID for signer with level BASELINE-B */
    private static final int WORKER_ID = 4711;

    /** Worker ID for TimeStampSigner */
    private static final int TS_WORKER_ID = 4712;

    /** Worker ID for signer with level BASELINE-LT */
    private static final int LT_WORKER_ID = 4713;

    /** Worker ID for signer with level BASELINE-LT with OCSP signed by another
     *  CA than the signer's.
     */
    private static final int LT_ALT_OCSP_WORKER_ID = 4714;

    /** Worker ID for time stamp signer with signer cert signed by another CA */
    private static final int SECOND_TS_WORKER_ID = 4718;

    /** Worker ID for signer with level BASELINE-LT with OCSP signed by another
     *  CA than the signer's and using a timestamp signer signed by yet
     *  another CA.
     */
    private static final int LT_ALT_OCSP_ALT_TSA_WORKER_ID = 4719;

    /** Worker ID for time stamp signer issued by a sub CA. */
    private static final int THIRD_TS_WORKER_ID = 4720;

    /** Worker ID for signer with level BASELINE-T issued by a sub CA, also
     *  using a TSA issued by the sub CA.
     */
    private static final int T_WORKER_ID = 4721;

    /** Worker ID for signer with level BASELINE-LTA. */
    private static final int LTA_WORKER_ID = 4722;

    /** Worker ID for signer with level BASELINE-LTA using CRL. */
    private static final int LTA_CRL_WORKER_ID = 4723;

    /** Worker ID for signer with level BASELINE-LTA using CRL with extra signature space
     * for large signatures
     */
    private static final int LTA_CRL_EXTRA_SIGNATURE_SPACE_WORKER_ID = 4724;

    private static final String CDP_URI_ROOTCA = "http://crl.signserver.org/rootca.crt";

    /** Class under test */
    private final AdESSigner instance = new MockedAdESSigner(null);

    private X509CertificateHolder rootcaCert;
    private X509CertificateHolder secondRootcaCert;
    private X509CertificateHolder thirdRootcaCert;

    public AdESSignerUnitTest() throws Exception {
        SignServerUtil.installBCProvider();
        setupWorkers();
    }

    private class MockOCSPDataLoader extends OCSPDataLoader {
        private final X509CertificateHolder rootcaCert;
        private final KeyPair rootcaKeyPair;

        public int numberOfLookups = 0;

        public MockOCSPDataLoader(final X509CertificateHolder rootcaCert,
                                  final KeyPair rootcaKeyPair) {
            this.rootcaCert = rootcaCert;
            this.rootcaKeyPair = rootcaKeyPair;
        }

        @Override
        public byte[] post(String url, byte[] content) {
            try {
                final OCSPReq req = new OCSPReq(content);
                final CertificateID certId =
                        req.getRequestList()[0].getCertID();

                final Date thisUpdate = new Date();
                final Date nextUpdate = new Date(thisUpdate.getTime() + 600000L);

                final OCSPResponse resp = new OCSPResponseBuilder()
                        .addResponse(new OcspRespObject(certId, CertificateStatus.GOOD, thisUpdate, nextUpdate, null))
                                .setResponseSignerCertificate(new JcaX509CertificateConverter().getCertificate(rootcaCert))
                                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                                .setChain(new X509CertificateHolder[] {rootcaCert})
                                .setSignatureAlgorithm("SHA256withRSA").build();

                numberOfLookups++;

                return resp.getResp().getEncoded();
            } catch (OCSPResponseBuilderException | CertificateException |
                     IOException ex) {
                throw new RuntimeException("Error generating mock OCSP response",
                                           ex);
            }
        }

    }

    private abstract class MockCRLDataLoader extends CommonsDataLoader {

        public int numberOfLookups = 0;

        @Override
        public DataLoader.DataAndUrl get(List<String> urlStrings) throws DSSException {
            numberOfLookups++;
            return doGet(urlStrings);
        }

        protected abstract DataAndUrl doGet(List<String> urlStrings);
    }

    // OCSP mock signing the response with the same CA as the signers
    private MockOCSPDataLoader ocspDataLoader;
    // Alternative OCSP mock using a different CA to sign the response
    private MockOCSPDataLoader otherOcspDataLoader;

    private MockCRLDataLoader crlDataLoader;

    private void setupWorkers()
            throws NoSuchAlgorithmException, NoSuchProviderException,
            CertBuilderException, CertificateException {

        final WorkerSessionMock workerMock = new WorkerSessionMock();
        workerSession = workerMock;
        processSession = workerMock;

        // Let's have the certs created a week ago
        long now = System.currentTimeMillis() - 7 * 24 * 60 * 60 * 1000;

        // first root CA
        final KeyPair rootcaKeyPair = CryptoUtils.generateRSA(2048);
        rootcaCert = new CertBuilder()
                .setNotBefore(new Date(now))
                .setSelfSignKeyPair(rootcaKeyPair)
                .setSignatureAlgorithm("SHA256withRSA")
                .setSubject("CN=Root, O=AdES Test, C=SE")
                .addExtension(new CertExt(Extension.keyUsage, false, new X509KeyUsage(X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign | X509KeyUsage.digitalSignature)))
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(true)))
                .build();

        final CertExt aia =
                new CertExt(Extension.authorityInfoAccess, false,
                            new AuthorityInformationAccess(AccessDescription.id_ad_ocsp,
                                new GeneralName(GeneralName.uniformResourceIdentifier, "http://ocsp.example.com")));

        Date thisUpdate = new Date();
        Date nextUpdate = new Date(thisUpdate.getTime() + 7 * 24 * 60 * 60 * 1000);
        X509CRLHolder rootcaCrl = new CRLBuilder()
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .setThisUpdate(thisUpdate)
                .setNextUpdate(nextUpdate)
                .setSignatureAlgorithm("SHA256withRSA")
                .build();

        // secondary root CA
        final KeyPair secondRootcaKeyPair = CryptoUtils.generateRSA(2048);
        secondRootcaCert = new CertBuilder()
                .setNotBefore(new Date(now + 24 * 60 * 60 * 1000))
                .setSelfSignKeyPair(secondRootcaKeyPair)
                .setSignatureAlgorithm("SHA256withRSA")
                .setSubject("CN=Second Root, O=AdES Test, C=SE")
                .addExtension(new CertExt(Extension.keyUsage, false, new X509KeyUsage(X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign | X509KeyUsage.digitalSignature)))
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(true)))
                .build();

        // third root CA
        final KeyPair thirdRootcaKeyPair = CryptoUtils.generateRSA(2048);
        thirdRootcaCert = new CertBuilder()
                .setNotBefore(new Date(now + 12 * 60 * 60 * 1000))
                .setSelfSignKeyPair(thirdRootcaKeyPair)
                .setSignatureAlgorithm("SHA256withRSA")
                .setSubject("CN=Third Root, O=AdES Test, C=SE")
                .addExtension(new CertExt(Extension.keyUsage, false, new X509KeyUsage(X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign | X509KeyUsage.digitalSignature)))
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(true)))
                .build();


        // sub CA, issued by "first root CA"
        final KeyPair subcaKeyPair = CryptoUtils.generateRSA(2048);
        final X509CertificateHolder subcaCert = new CertBuilder()
                .setNotBefore(new Date(now + 2 * 24 * 60 * 60 * 1000))
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .setSubjectPublicKey(subcaKeyPair.getPublic())
                .setSignatureAlgorithm("SHA256withRSA")
                .setSubject("CN=SubCA, O=AdES Test, C=SE")
                .addExtension(new CertExt(Extension.keyUsage, false, new X509KeyUsage(X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign | X509KeyUsage.digitalSignature)))
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(true)))
                .addExtension(aia)
                .build();

        // WORKER
        final KeyPair signerKeyPair = CryptoUtils.generateRSA(2048);
        final X509CertificateHolder signerCert = new CertBuilder()
            .setNotBefore(new Date(now + 3 * 24 * 60 * 60 * 1000))
            .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
            .setIssuer(rootcaCert.getSubject())
            .setSubjectPublicKey(signerKeyPair.getPublic())
            .setSignatureAlgorithm("SHA256withRSA")
            .setSubject("CN=Signer 1, O=AdES Test, C=SE")
            .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
            .addExtension(new CertExt(Extension.keyUsage, false, new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.nonRepudiation)))
            .addExtension(aia)
            .build();

        final List<Certificate> certChain =
                Arrays.<Certificate>asList(converter.getCertificate(signerCert),
                                           converter.getCertificate(rootcaCert));


        final Certificate signerCertificate = certChain.get(0);

        final MockedCryptoToken token = new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, certChain, PROVIDER);

        // TSA
        final CertExt ku =
                new CertExt(Extension.extendedKeyUsage, true,
                            new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

        final KeyPair tsKeyPair = CryptoUtils.generateRSA(2048);
        final X509CertificateHolder tsSignerCert = new CertBuilder()
            .setNotBefore(new Date(now + 2 * 24 * 60 * 60 * 1000))
            .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
            .setIssuer(rootcaCert.getSubject())
            .setSubjectPublicKey(tsKeyPair.getPublic())
            .setSignatureAlgorithm("SHA256withRSA")
            .setSubject("CN=TS Signer 1, O=AdES Test, C=SE")
            .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
            .addExtension(ku)
            .addExtension(aia)
            .build();

        final List<Certificate> tsCertChain =
                Arrays.<Certificate>asList(converter.getCertificate(tsSignerCert),
                                           converter.getCertificate(rootcaCert));
        final Certificate tsCert = tsCertChain.get(0);
        final MockedCryptoToken tsToken =
                new MockedCryptoToken(tsKeyPair.getPrivate(),
                                      tsKeyPair.getPublic(), tsCert,
                                      tsCertChain, PROVIDER);

        // sedond TSA
        final KeyPair secondTsKeyPair = CryptoUtils.generateRSA(2048);
        final X509CertificateHolder secondTsSignerCert = new CertBuilder()
            .setNotBefore(new Date(now + 2 * 24 * 60 * 60 * 1000))
            .setIssuerPrivateKey(thirdRootcaKeyPair.getPrivate())
            .setIssuer(thirdRootcaCert.getSubject())
            .setSubjectPublicKey(secondTsKeyPair.getPublic())
            .setSignatureAlgorithm("SHA256withRSA")
            .setSubject("CN=TS Signer 2, O=AdES Test, C=SE")
            .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
            .addExtension(ku)
            .addExtension(aia)
            .build();

        final List<Certificate> secondTsCertChain =
                Arrays.<Certificate>asList(converter.getCertificate(secondTsSignerCert),
                                           converter.getCertificate(thirdRootcaCert));
        final Certificate secondTsCert = secondTsCertChain.get(0);
        final MockedCryptoToken secondTsToken =
                new MockedCryptoToken(secondTsKeyPair.getPrivate(),
                                      secondTsKeyPair.getPublic(), secondTsCert,
                                      secondTsCertChain, PROVIDER);

        // Worker with cert with OCSP revocation info
        final KeyPair ltSignerKeyPair = CryptoUtils.generateRSA(2048);
        final X509CertificateHolder ltSignerCert = new CertBuilder()
            .setNotBefore(new Date(now + 3 * 24 * 60 * 60 * 1000))
            .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
            .setIssuer(rootcaCert.getSubject())
            .setSubjectPublicKey(ltSignerKeyPair.getPublic())
            .setSignatureAlgorithm("SHA256withRSA")
            .setSubject("CN=Signer 2, O=AdES Test, C=SE")
            .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
            .addExtension(new CertExt(Extension.keyUsage, false, new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.nonRepudiation)))
            .addExtension(aia)
            .build();


        final List<Certificate> ltCertChain =
                Arrays.<Certificate>asList(converter.getCertificate(ltSignerCert),
                                           converter.getCertificate(rootcaCert));

        final Certificate ltCert = ltCertChain.get(0);
        final MockedCryptoToken ltToken =
                new MockedCryptoToken(ltSignerKeyPair.getPrivate(),
                                      ltSignerKeyPair.getPublic(), ltCert,
                                      ltCertChain, PROVIDER);

        // Worker with cert with CRL revocation info
        final X509CertificateHolder ltCrlSignerCert = new CertBuilder()
            .setNotBefore(new Date(now + 3 * 24 * 60 * 60 * 1000))
            .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
            .setIssuer(rootcaCert.getSubject())
            .setSubjectPublicKey(ltSignerKeyPair.getPublic())
            .setSignatureAlgorithm("SHA256withRSA")
            .setSubject("CN=Signer 2 with CRL, O=AdES Test, C=SE")
            .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
            .addExtension(new CertExt(Extension.keyUsage, false, new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.nonRepudiation)))
            .addCDPURI(CDP_URI_ROOTCA)
            .build();


        final List<Certificate> ltCrlCertChain =
                Arrays.<Certificate>asList(converter.getCertificate(ltCrlSignerCert),
                                           converter.getCertificate(rootcaCert));

        final Certificate ltCrlCert = ltCrlCertChain.get(0);
        final MockedCryptoToken ltCrlToken =
                new MockedCryptoToken(ltSignerKeyPair.getPrivate(),
                                      ltSignerKeyPair.getPublic(), ltCrlCert,
                                      ltCrlCertChain, PROVIDER);

        // Worker with cert with CRL revocation info Large signature
        final X509CertificateHolder ltCrlLargeSignerCert = new CertBuilder()
                .setNotBefore(new Date(now + 3 * 24 * 60 * 60 * 1000))
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .setSubjectPublicKey(ltSignerKeyPair.getPublic())
                .setSignatureAlgorithm("SHA256withRSA")
                .setSubject("CN=Signer 2 with CRL, O=AdES Test, C=SE")
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
                .addExtension(new CertExt(Extension.keyUsage, false, new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.nonRepudiation)))
                .addExtension(new CertExt(new ASN1ObjectIdentifier("1.2.3"), false, new DEROctetString(new byte[10000])))
                .addCDPURI(CDP_URI_ROOTCA)
                .build();

        final List<Certificate> ltCrlLargeSignatureCertChain =
                Arrays.asList(converter.getCertificate(ltCrlLargeSignerCert),
                        converter.getCertificate(rootcaCert));

        final Certificate ltCrlLargeSignatureCert = ltCrlCertChain.get(0);
        final MockedCryptoToken ltCrlLargeSignatureToken =
                new MockedCryptoToken(ltSignerKeyPair.getPrivate(),
                        ltSignerKeyPair.getPublic(), ltCrlLargeSignatureCert,
                        ltCrlLargeSignatureCertChain, PROVIDER);

        // AdESSigner with BASELINE-B
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerName("TestAdESSigner1")
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withSignatureAlgorithm("SHA256withRSA")
                .build();
        workerMock.setupWorker(WORKER_ID, CRYPTOTOKEN_CLASSNAME, config,
                new AdESSigner() {
                    @Override
                    public ICryptoTokenV4 getCryptoToken(final IServices services) {
                        return token;
                    }
                });
        workerSession.reloadConfiguration(WORKER_ID);

        // TSA with OCSP
        final WorkerConfig tsConfig = WorkerConfigBuilder.builder()
                .withWorkerName("TestTimeStampSigner")
                .build();

        tsConfig.setProperty("ACCEPTANYPOLICY", "true");
        tsConfig.setProperty("DEFAULTTSAPOLICYOID", "1.3.6.1.4.1.22408.1.2.3.45");

        workerMock.setupWorker(TS_WORKER_ID, CRYPTOTOKEN_CLASSNAME, tsConfig,
                new TimeStampSigner() {
                    @Override
                    public ICryptoTokenV4 getCryptoToken(final IServices services) {
                        return tsToken;
                    }
                });
        workerSession.reloadConfiguration(TS_WORKER_ID);

        // TSA with OCSP
        final WorkerConfig secondTsConfig = WorkerConfigBuilder.builder()
                .withWorkerName("TestTimeStampSigner2")
                .build();

        secondTsConfig.setProperty("ACCEPTANYPOLICY", "true");
        secondTsConfig.setProperty("DEFAULTTSAPOLICYOID", "1.3.6.1.4.1.22408.1.2.3.45");

        workerMock.setupWorker(SECOND_TS_WORKER_ID, CRYPTOTOKEN_CLASSNAME,
                               secondTsConfig,
                new TimeStampSigner() {
                    @Override
                    public ICryptoTokenV4 getCryptoToken(final IServices services) {
                        return secondTsToken;
                    }
                });
        workerSession.reloadConfiguration(SECOND_TS_WORKER_ID);

        ocspDataLoader = new MockOCSPDataLoader(rootcaCert, rootcaKeyPair);

        // AdESSigner with BASELINE-LT (using OCSP revocation info)
        final WorkerConfig ltConfig = AdESWorkerConfigBuilder.builder()
                .withWorkerName("TestAdESSigner2")
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_LT.name())
                .withSignatureAlgorithm("SHA256withRSA")
                .withTsaWorker(Integer.toString(TS_WORKER_ID))
                .build();
        workerMock.setupWorker(LT_WORKER_ID, CRYPTOTOKEN_CLASSNAME, ltConfig,
                new AdESSigner() {
                    @Override
                    public ICryptoTokenV4 getCryptoToken(final IServices services) {
                        return ltToken;
                    }

                    @Override
                    InternalProcessSessionLocal getWorkerSession(RequestContext requestContext) {
                        return workerMock;
                    }

                    @Override
                    OCSPDataLoader createOcspDataLoader() {
                        return ocspDataLoader;
                    }
                });
        workerSession.reloadConfiguration(LT_WORKER_ID);

        otherOcspDataLoader =
                new MockOCSPDataLoader(secondRootcaCert, secondRootcaKeyPair);

        // AdESSigner with BASELINE-LT, with OCSP responses signed by a different CA
        final WorkerConfig ltAltOcspConfig = AdESWorkerConfigBuilder.builder()
                .withWorkerName("TestAdESSigner3")
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_LT.name())
                .withSignatureAlgorithm("SHA256withRSA")
                .withTsaWorker(Integer.toString(TS_WORKER_ID))
                .build();
        workerMock.setupWorker(LT_ALT_OCSP_WORKER_ID, CRYPTOTOKEN_CLASSNAME,
                               ltAltOcspConfig,
                new AdESSigner() {
                    @Override
                    public ICryptoTokenV4 getCryptoToken(final IServices services) {
                        return ltToken;
                    }

                    @Override
                    InternalProcessSessionLocal getWorkerSession(RequestContext requestContext) {
                        return workerMock;
                    }

                    @Override
                    OCSPDataLoader createOcspDataLoader() {
                        return otherOcspDataLoader;
                    }
                });
        workerSession.reloadConfiguration(LT_ALT_OCSP_WORKER_ID);

        // AdESSigner with BASELINE-LT, with OCSP responses signed by another CA
        // and using TSA with a signer cert issued by a different CA than the signer
        final WorkerConfig ltAltOcspAltTsaConfig = AdESWorkerConfigBuilder.builder()
                .withWorkerName("TestAdESSigner4")
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_LT.name())
                .withSignatureAlgorithm("SHA256withRSA")
                .withTsaWorker(Integer.toString(SECOND_TS_WORKER_ID))
                .withTrustAnchors(CertTools.getPemFromCertificate(converter.getCertificate(thirdRootcaCert)))
                .build();
        workerMock.setupWorker(LT_ALT_OCSP_ALT_TSA_WORKER_ID, CRYPTOTOKEN_CLASSNAME,
                               ltAltOcspAltTsaConfig,
                new AdESSigner() {
                    @Override
                    public ICryptoTokenV4 getCryptoToken(final IServices services) {
                        return ltToken;
                    }

                    @Override
                    InternalProcessSessionLocal getWorkerSession(RequestContext requestContext) {
                        return workerMock;
                    }

                    @Override
                    OCSPDataLoader createOcspDataLoader() {
                        return otherOcspDataLoader;
                    }
                });
        workerSession.reloadConfiguration(LT_ALT_OCSP_ALT_TSA_WORKER_ID);

        // Timestamp signer with signer cert issued by sub CA
        final KeyPair thirdTsKeyPair = CryptoUtils.generateRSA(2048);
        final X509CertificateHolder thirdTsSignerCert = new CertBuilder()
            .setIssuerPrivateKey(subcaKeyPair.getPrivate())
            .setIssuer(subcaCert.getSubject())
            .setSubjectPublicKey(thirdTsKeyPair.getPublic())
            .setSignatureAlgorithm("SHA256withRSA")
            .setSubject("CN=TS Signer 3, O=AdES Test, C=SE")
            .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
            .addExtension(ku)
            .addExtension(aia)
            .build();

        final List<Certificate> thirdTsCertChain =
                Arrays.<Certificate>asList(converter.getCertificate(thirdTsSignerCert),
                                           converter.getCertificate(subcaCert),
                                           converter.getCertificate(rootcaCert));
        final Certificate thirdTsCert = thirdTsCertChain.get(0);
        final MockedCryptoToken thirdTsToken =
                new MockedCryptoToken(thirdTsKeyPair.getPrivate(),
                                      thirdTsKeyPair.getPublic(), thirdTsCert,
                                      thirdTsCertChain, PROVIDER);

        final WorkerConfig thirdTsConfig = WorkerConfigBuilder.builder()
                .withWorkerName("TestTimeStampSigner3")
                .build();

        thirdTsConfig.setProperty("ACCEPTANYPOLICY", "true");
        thirdTsConfig.setProperty("DEFAULTTSAPOLICYOID", "1.3.6.1.4.1.22408.1.2.3.45");

        workerMock.setupWorker(THIRD_TS_WORKER_ID, CRYPTOTOKEN_CLASSNAME,
                               thirdTsConfig,
                new TimeStampSigner() {
                    @Override
                    public ICryptoTokenV4 getCryptoToken(final IServices services) {
                        return thirdTsToken;
                    }
                });
        workerSession.reloadConfiguration(THIRD_TS_WORKER_ID);

        // AdES signer issued by the sub CA
        final KeyPair signerSubKeyPair = CryptoUtils.generateRSA(2048);
        final X509CertificateHolder signerSubCert = new CertBuilder()
            .setNotBefore(new Date(now + 4 * 24 * 60 * 60 * 1000))
            .setIssuerPrivateKey(subcaKeyPair.getPrivate())
            .setIssuer(subcaCert.getSubject())
            .setSubjectPublicKey(signerSubKeyPair.getPublic())
            .setSignatureAlgorithm("SHA256withRSA")
            .setSubject("CN=Signer Sub, O=AdES Test, C=SE")
            .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
            .addExtension(aia)
            .build();

        final List<Certificate> subCertChain =
                Arrays.<Certificate>asList(converter.getCertificate(signerSubCert),
                                           converter.getCertificate(subcaCert),
                                           converter.getCertificate(rootcaCert));

        final Certificate signerSubCertificate = subCertChain.get(0);

        final MockedCryptoToken tokenSub =
                new MockedCryptoToken(signerSubKeyPair.getPrivate(),
                                      signerSubKeyPair.getPublic(),
                                      signerSubCertificate, subCertChain,
                                      PROVIDER);

        // AdESSigner with BASELINE-T
        final WorkerConfig configT = AdESWorkerConfigBuilder.builder()
                .withWorkerName("TestAdESSignerLevelT")
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_T.name())
                .withSignatureAlgorithm("SHA256withRSA")
                .withTsaWorker(Integer.toString(THIRD_TS_WORKER_ID))
                .build();
        workerMock.setupWorker(T_WORKER_ID, CRYPTOTOKEN_CLASSNAME, configT,
                new AdESSigner() {
                    @Override
                    public ICryptoTokenV4 getCryptoToken(final IServices services) {
                        return tokenSub;
                    }

                    @Override
                    InternalProcessSessionLocal getWorkerSession(RequestContext requestContext) {
                        return workerMock;
                    }
                });
        workerSession.reloadConfiguration(T_WORKER_ID);

        // AdESSigner with BASELINE-LT (using OCSP revocation info)
        final WorkerConfig ltaConfig = AdESWorkerConfigBuilder.builder()
                .withWorkerName("TestAdESSignerLevelLTA")
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_LTA.name())
                .withSignatureAlgorithm("SHA256withRSA")
                .withTsaWorker(Integer.toString(TS_WORKER_ID))
                .build();
        workerMock.setupWorker(LTA_WORKER_ID, CRYPTOTOKEN_CLASSNAME, ltaConfig,
                new AdESSigner() {
                    @Override
                    public ICryptoTokenV4 getCryptoToken(final IServices services) {
                        return ltToken;
                    }

                    @Override
                    InternalProcessSessionLocal getWorkerSession(RequestContext requestContext) {
                        return workerMock;
                    }

                    @Override
                    OCSPDataLoader createOcspDataLoader() {
                        return ocspDataLoader;
                    }
                });
        workerSession.reloadConfiguration(LTA_WORKER_ID);

        // AdESSigner with BASELINE-LTA (using CRL revocation info)
        crlDataLoader = new MockCRLDataLoader() {

            @Override
            public DataLoader.DataAndUrl doGet(List<String> urlStrings) throws DSSException {
                LOG.debug(">doGet(" + urlStrings + ")");
                DataAndUrl result = null;

                outer: for (String url : urlStrings) {
                    switch (url) {
                        case CDP_URI_ROOTCA:
                            try {
                                result = new DataAndUrl(rootcaCrl.getEncoded(), url);
                            } catch (IOException ex) {
                                throw new RuntimeException(ex);
                            }
                        break outer;
                    }
                }

                if (result == null) {
                    throw new UnsupportedOperationException("Not yet mocked CDP URL(s): " + urlStrings);
                }

                return result;
            }

        };

        // AdESSigner with BASELINE-LTA with CRL
        final WorkerConfig ltaCrlConfig = AdESWorkerConfigBuilder.builder()
                .withWorkerName("TestAdESSignerLevelLTA_CRL")
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_LTA.name())
                .withSignatureAlgorithm("SHA256withRSA")
                .withTsaWorker(Integer.toString(TS_WORKER_ID))
                .build();
        workerMock.setupWorker(LTA_CRL_WORKER_ID, CRYPTOTOKEN_CLASSNAME, ltaCrlConfig,
                new AdESSigner() {
                    @Override
                    public ICryptoTokenV4 getCryptoToken(final IServices services) {
                        return ltCrlToken;
                    }

                    @Override
                    InternalProcessSessionLocal getWorkerSession(RequestContext requestContext) {
                        return workerMock;
                    }

                    @Override
                    OCSPDataLoader createOcspDataLoader() {
                        return ocspDataLoader;
                    }

                    @Override
                    DataLoader createCrlDataLoader() {
                        return crlDataLoader;
                    }

                });
        workerSession.reloadConfiguration(LTA_CRL_WORKER_ID);

        // AdESSigner with BASELINE-LTA with CRL - Extra signature space
        final WorkerConfig ltaCrlLargeSignatureConfig = AdESWorkerConfigBuilder.builder()
                .withWorkerName("TestAdESSignerLevelLTA_CRL_LargeSignature")
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_LTA.name())
                .withSignatureAlgorithm("SHA256withRSA")
                .withTsaWorker(Integer.toString(TS_WORKER_ID))
                .withExtraSignatureSpace("5000")
                .build();
        workerMock.setupWorker(LTA_CRL_EXTRA_SIGNATURE_SPACE_WORKER_ID, CRYPTOTOKEN_CLASSNAME, ltaCrlLargeSignatureConfig,
                new AdESSigner() {
                    @Override
                    public ICryptoTokenV4 getCryptoToken(final IServices services) {
                        return ltCrlLargeSignatureToken;
                    }

                    @Override
                    InternalProcessSessionLocal getWorkerSession(RequestContext requestContext) {
                        return workerMock;
                    }

                    @Override
                    OCSPDataLoader createOcspDataLoader() {
                        return ocspDataLoader;
                    }

                    @Override
                    DataLoader createCrlDataLoader() {
                        return crlDataLoader;
                    }

                });
        workerSession.reloadConfiguration(LTA_CRL_EXTRA_SIGNATURE_SPACE_WORKER_ID);
    }

    /**
     * Test of setting the worker required property.
     */
    @Test
    public void testAdESSetSignatureLevel() {
        LOG.info("testAdESSetSignatureLevel");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        assertTrue("no config errors", instance.getFatalErrors(null).isEmpty());
    }

    /**
     * Tests the failure when an invalid property is set.
     */
    @Test
    public void testAdESSetInvalidSignatureLevel() {
        LOG.info("testAdESSetInvalidSignatureLevel");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel("Dummy_XXX")
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        final String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        final String expectedMessage =
                "Unknown signature level: Dummy_XXX, supported values: BASELINE-B";
        assertTrue("config errs: " + errors,
                            errors.contains(expectedMessage));
    }

    /**
     * Tests the failure when the required worker property is not set.
     */
    @Test
    public void testAdESWithoutSignatureLevel() {
        LOG.info("testAdESWithoutSignatureLevel");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("config errs: " + errors, errors.contains("Missing required property SIGNATURE_LEVEL"));
    }

    /**
     * Tests the setting SHA256withRSA algorithms to SIGNATUREALGORITHM property.
     */
    @Test
    public void testAdESSetSignatureAlgorithm_SHA256withRSA() {
        LOG.info("testAdESSetSignatureAlgorithm_SHA256withRSA");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withSignatureAlgorithm("SHA256withRSA")
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        assertTrue("no config errors", instance.getFatalErrors(null).isEmpty());
    }

    /**
     * Tests the setting SHA384withRSA algorithms to SIGNATUREALGORITHM property.
     */
    @Test
    public void testAdESSetSignatureAlgorithm_SHA384withRSA() {
        LOG.info("testAdESSetSignatureAlgorithm_SHA384withRSA");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withSignatureAlgorithm("SHA384withRSA")
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        assertTrue("no config errors", instance.getFatalErrors(null).isEmpty());
    }

    /**
     * Tests the setting SHA512withRSA algorithms to SIGNATUREALGORITHM property.
     */
    @Test
    public void testAdESSetSignatureAlgorithm_SHA512withRSA() {
        LOG.info("testAdESSetSignatureAlgorithm_SHA512withRSA");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withSignatureAlgorithm("SHA512withRSA")
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        assertTrue("no config errors", instance.getFatalErrors(null).isEmpty());
    }

    /**
     * Tests the setting SHA256withRSAandMGF1 algorithms to SIGNATUREALGORITHM property.
     */
    @Test
    public void testAdESSetSignatureAlgorithm_SHA256withRSAandMGF1() {
        LOG.info("testAdESSetSignatureAlgorithm_SHA256withRSAandMGF1");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withSignatureAlgorithm("SHA256withRSAandMGF1")
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        assertTrue("no config errors", instance.getFatalErrors(null).isEmpty());
    }

    /**
     * Tests the setting SHA384withRSAandMGF1 algorithms to SIGNATUREALGORITHM property.
     */
    @Test
    public void testAdESSetSignatureAlgorithm_SHA384withRSAandMGF1() {
        LOG.info("testAdESSetSignatureAlgorithm_SHA384withRSAandMGF1");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withSignatureAlgorithm("SHA384withRSAandMGF1")
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        assertTrue("no config errors", instance.getFatalErrors(null).isEmpty());
    }

    /**
     * Tests the setting SHA512withRSAandMGF1 algorithms to SIGNATUREALGORITHM property.
     */
    @Test
    public void testAdESSetSignatureAlgorithm_SHA512withRSAandMGF1() {
        LOG.info("testAdESSetSignatureAlgorithm_SHA512withRSAandMGF1");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withSignatureAlgorithm("SHA512withRSAandMGF1")
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        assertTrue("no config errors", instance.getFatalErrors(null).isEmpty());
    }

    /**
     * Tests the setting invalid algorithms to SIGNATUREALGORITHM property.
     */
    @Test
    public void testAdESSetInvalidSignatureAlgorithm() {
        LOG.info("testAdESSetInvalidSignatureAlgorithm");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withSignatureAlgorithm("DummyAlgorithm")
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        final String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("Unknown signature algorithm: DummyAlgorithm"));
    }

    /**
     * Tests that SIGNATUREALGORITHM property is optional.
     */
    @Test
    public void testAdESWithoutSignatureAlgorithm() {
        LOG.info("testAdESWithoutSignatureAlgorithm");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        assertTrue("no config errors", instance.getFatalErrors(null).isEmpty());
    }

    /**
     * Tests the setting SHA256 algorithms to DIGESTALGORITHM property.
     */
    @Test
    public void testAdESSetDigestAlgorithm_SHA256() {
        LOG.info("testAdESSetDigestAlgorithm_SHA256");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withDigestAlgorithm("SHA256")
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        assertTrue("no config errors", instance.getFatalErrors(null).isEmpty());
    }

    /**
     * Tests the setting SHA384 algorithms to DIGESTALGORITHM property.
     */
    @Test
    public void testAdESSetDigestAlgorithm_SHA384() {
        LOG.info("testAdESSetDigestAlgorithm_SHA384");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withDigestAlgorithm("SHA384")
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        assertTrue("no config errors", instance.getFatalErrors(null).isEmpty());
    }

    /**
     * Tests the setting SHA512 algorithms to DIGESTALGORITHM property.
     */
    @Test
    public void testAdESSetDigestAlgorithm_SHA512() {
        LOG.info("testAdESSetDigestAlgorithm_SHA512");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withDigestAlgorithm("SHA512")
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        assertTrue("no config errors", instance.getFatalErrors(null).isEmpty());
    }

    /**
     * Tests the setting invalid algorithms to DIGESTALGORITHM property.
     */
    @Test
    public void testAdESSetInvalidDigestAlgorithm() {
        LOG.info("testAdESSetInvalidDigestAlgorithm");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withDigestAlgorithm("DummyAlgorithm")
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        final String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("Unknown digest algorithm: DummyAlgorithm"));
    }

    /**
     * Tests the setting digest algorithms and signature algorithm properties.
     */
    @Test
    public void testAdESSetDigestAlgorithmAndSigningAlgorithm() {
        LOG.info("testAdESSetDigestAlgorithmAndSigningAlgorithm");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withDigestAlgorithm("SHA512")
                .withSignatureAlgorithm("SHA256withRSA")
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        final String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("DIGESTALGORITHM"));
        assertTrue("conf errs: " + errors, errors.contains("SIGNATUREALGORITHM"));
    }

    /**
     * Tests that setting both TSA_WORKER and TSA_URL results in a config error.
     */
    @Test
    public void testAdESBothTsaWorkerAndUrlNotAllowed() {
        LOG.info("testAdESBothTsaWorkerAndUrlNotAllowed");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withTsaWorker("TimeStampSigner")
                .withTsaUrl("http://localhost:8080/signserver/tsa?workerName=TimeStampSigner")
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        final String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("TSA_WORKER"));
        assertTrue("conf errs: " + errors, errors.contains("TSA_URL"));
    }

    /**
     * Tests that setting ADD_CONTENT_TIMESTAMP to an illegal value is not allowed.
     */
    @Test
    public void testAdESAddContentTimestampIllegal() {
        LOG.info("testAdESAddContentTimestampIllegal");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withAddContentTimestamp("illegal")
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        final String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors,
                            errors.contains("ADD_CONTENT_TIMESTAMP"));
    }

    /**
     * Tests that setting signature level BASELINE-T required TSA.
     */
    @Test
    public void testAdESSignatureLevelBaselineTRequiredTsa() {
        LOG.info("testAdESSignatureLevelBaselineTRequiredTsa");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_T.name())
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        final String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors,
                            errors.contains("TSA_WORKER or TSA_URL"));
    }

    /**
     * Tests that setting signature level BASELINE-LT required TSA.
     */
    @Test
    public void testAdESSignatureLevelBaselineLTRequiredTsa() {
        LOG.info("testAdESSignatureLevelBaselineTRequiredTsa");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_LT.name())
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        final String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors,
                            errors.contains("TSA_WORKER or TSA_URL"));
    }

    /**
     * Tests that setting an invalid value for TRUSTANCHORS results in a
     * configuration error.
     */
    @Test
    public void testAdESInvalidTrustanchors() {
        LOG.info("testAdESInvalidTrustanchors");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_LT.name())
                .withTrustAnchors("_invalid_")
                .build();
        // when
        instance.init(WORKER_ID, config, null, null);
        // then
        final String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errors: " + errors, errors.contains("TRUSTANCHORS"));
    }

    /**
     * Test PAdES setting extra signature space property.
     */
    @Test
    public void testPAdESSetExtraSignatureSpace() {
        LOG.info("testPAdESSetExtraSignatureSpace");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withDigestAlgorithm("SHA256")
                .withExtraSignatureSpace("5000")
                .build();
        // when
        instance.init(LTA_CRL_EXTRA_SIGNATURE_SPACE_WORKER_ID, config, null, null);
        // then
        assertTrue("no config errors", instance.getFatalErrors(null).isEmpty());
    }

    /**
     * Tests the setting invalid number for extra signature space property.
     */
    @Test
    public void testPAdESSetInvalidExtraSignatureSpace() {
        LOG.info("testPAdESSetInvalidExtraSignatureSpace");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.PAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withDigestAlgorithm("SHA256")
                .withExtraSignatureSpace("test")
                .build();
        // when
        instance.init(LTA_CRL_EXTRA_SIGNATURE_SPACE_WORKER_ID, config, null, null);
        // then
        final String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("test is not a valid number"));
    }

    /**
     * Tests the failure when setting extra signature space property for XAdES.
     */
    @Test
    public void testXAdESSetExtraSignatureSpace() {
        LOG.info("testXAdESSetExtraSignatureSpace");
        // given
        final WorkerConfig config = AdESWorkerConfigBuilder.builder()
                .withWorkerType(WorkerType.PROCESSABLE.name())
                .withSignatureFormat(AdESSignatureFormat.XAdES.name())
                .withSignatureLevel(AdESSignatureLevel.BASELINE_B.name())
                .withSignaturePackaging(SignaturePackaging.ENVELOPED.name())
                .withDigestAlgorithm("SHA256")
                .withExtraSignatureSpace("5000")
                .build();
        // when
        instance.init(LTA_CRL_EXTRA_SIGNATURE_SPACE_WORKER_ID, config, null, null);
        // then
        final String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("EXTRA_SIGNATURE_SPACE property is not supported with XAdES"));
    }

    private void assertSignPDF(final File sampleFile, final int workerId, final boolean expectTimestamp, final boolean expectArchiveTimestamp, final boolean expectOcsp, boolean expectCrl, final boolean expectTProfile, final boolean expectLTProfile, final boolean expectLTAProfile)
            throws Exception {
        final RequestContext context = new RequestContext();

        try (
                CloseableReadableData requestData = createRequestDataKeepingFile(sampleFile);
                CloseableWritableData responseData = createResponseData(true)
        ) {
            final SignatureResponse response =
                    (SignatureResponse) processSession.process(createAdminInfo(),
                            new WorkerIdentifier(workerId),
                            new SignatureRequest(200, requestData, responseData),
                            context);

            final DSSDocument document = new FileDocument( response.getResponseData().getAsFile());
            final PDFDocumentValidator documentValidator =
                    new PDFDocumentValidator(document);

            final List<AdvancedSignature> signatures =
                    documentValidator.getSignatures();

            assertEquals("Number of signatures", 1, signatures.size());

            final AdvancedSignature sig = signatures.get(0);

            assertEquals("Digest algorithm", DigestAlgorithm.SHA256, sig.getDigestAlgorithm());
            assertEquals("Signature algorithm", SignatureAlgorithm.RSA_SHA256, sig.getSignatureAlgorithm());

            sig.checkSignatureIntegrity();
            PAdESSignature pades = (PAdESSignature) sig;
            byte[] originalData = pades.getPdfRevision().getRevisionCoveredBytes();
            CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(originalData), pades.getCmsSignedData().getEncoded());

            // always should fulfill level B
            assertTrue("Has B profile", pades.hasBProfile());

            assertEquals("Has T profile", expectTProfile, pades.hasTProfile());
            assertEquals("Has LT profile", expectLTProfile,
                         pades.hasLTProfile());
            assertEquals("Has LTA profil", expectLTAProfile,
                         pades.hasLTAProfile());

            // check revocation
            final ListRevocationSource<OCSP> completeOcspSource =
                    pades.getCompleteOCSPSource();
            assertEquals("OCSP revocation tokens", expectOcsp,
                         !completeOcspSource.getAllRevocationBinaries().isEmpty());
            ListRevocationSource<CRL> completeCrlSource =
                    pades.getCompleteCRLSource();
            assertEquals("CRL revocation tokens", expectCrl,
                         !completeCrlSource.getAllRevocationBinaries().isEmpty());

            assertVerifiedCms(cms, SignatureAlgorithm.RSA_SHA256,
                              PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(),
                              null,
                              expectTimestamp ? DigestAlgorithm.SHA256.getOid() : null,
                              null, null,
                              null,
                              expectArchiveTimestamp ? DigestAlgorithm.SHA256.getOid() : null);

            // Document validation using DSS
            assertValidated(document);
        }
    }

    protected void assertValidated(DSSDocument document) throws IOException, CertificateException {
        // First, we need a Certificate verifier
        CertificateVerifier cv = new CommonCertificateVerifier();

        // We can inject several sources. eg: OCSP, CRL, AIA, trusted lists

        // Capability to download resources from AIA
        cv.setDataLoader(ocspDataLoader);

        // Capability to request OCSP Responders
        cv.setOcspSource(new OnlineOCSPSource(ocspDataLoader));

        // Capability to download CRL
        cv.setCrlSource(new OnlineCRLSource(ocspDataLoader));

        // Create an instance of a trusted certificate source
        CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
        // import the keystore as trusted
        final CertificateToken rootToken1 = new CertificateToken(converter.getCertificate(rootcaCert));
        trustedCertSource.addCertificate(rootToken1);
        final CertificateToken rootToken2 = new CertificateToken(converter.getCertificate(secondRootcaCert));
        trustedCertSource.addCertificate(rootToken2);
        final CertificateToken rootToken3 = new CertificateToken(converter.getCertificate(thirdRootcaCert));
        trustedCertSource.addCertificate(rootToken3);

        // Add trust anchors (trusted list, keystore,...) to a list of trusted certificate sources
        // Hint : use method {@code CertificateVerifier.setTrustedCertSources(certSources)} in order to overwrite the existing list
        cv.addTrustedCertSources(trustedCertSource);

        // Additionally add missing certificates to a list of adjunct certificate sources
        //cv.addAdjunctCertSources(adjunctCertSource);

        // Here is the document to be validated (any kind of signature file)
        //DSSDocument document = new FileDocument(new File("src/test/resources/signature-pool/signedXmlXadesLT.xml"));

        // We create an instance of DocumentValidator
        // It will automatically select the supported validator from the classpath
        SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(document);

        // We add the certificate verifier (which allows to verify and trust certificates)
        documentValidator.setCertificateVerifier(cv);

        // Here, everything is ready. We can execute the validation (for the example, we use the default and embedded
        // validation policy)
        Reports reports = documentValidator.validateDocument();

        // We have 3 reports
        // The diagnostic data which contains all used and static data
        //DiagnosticData diagnosticData = reports.getDiagnosticData();

        // The detailed report which is the result of the process of the diagnostic data and the validation policy
        //DetailedReport detailedReport = reports.getDetailedReport();

        // The simple report is a summary of the detailed report (more user-friendly)
        SimpleReport simpleReport = reports.getSimpleReport();
        LOG.info("\nSimple report:\n" + reports.getXmlSimpleReport());

        LOG.info("\nDetailed report:\n" + reports.getXmlDetailedReport());

        assertTrue("isValid", simpleReport.isValid(simpleReport.getFirstSignatureId())); // XXX we only look at first here

        List<String> signatureErrors = simpleReport.getErrors(simpleReport.getFirstSignatureId());

        // TODO: We need to create a trusted list to get rid of this
        signatureErrors.remove("Unable to build a certificate chain until a trusted list!");

        final List<String> expectedErrors = Arrays.asList();

        assertEquals("signatureErrors", expectedErrors.toString(), signatureErrors.toString());
    }

    /**
     * Test sign and verify a sample PDF file.
     * @throws Exception in case of test error
     */
    @Test
    public void testSignPDF() throws Exception {
        File sampleFile = new File(PathUtil.getAppHome(), "res/test/pdf/sample.pdf");
        LOG.debug("Tests signing of " + sampleFile.getName());

        assertSignPDF(sampleFile, WORKER_ID, false, false, false, false, false, false,
                      false);
    }

    /**
     * Test sign and verify a sample PDF file using a level BASELINE-LT signer
     * @throws Exception in case of test error
     */
    @Test
    public void testSignPDFLevelLT() throws Exception {
        File sampleFile = new File(PathUtil.getAppHome(), "res/test/pdf/sample.pdf");
        LOG.debug("Tests signing of " + sampleFile.getName());

        ocspDataLoader.numberOfLookups = 0;
        assertSignPDF(sampleFile, LT_WORKER_ID, true, false, true, false, true, true,
                      false);

        assertEquals("Number of OCSP lookups", 2 + 2, ocspDataLoader.numberOfLookups);
    }

    /**
     * Test sign and verify a sample PDF file using a level BASELINE-LTA signer
     * @throws Exception in case of test error
     */
    @Test
    public void testSignPDFLevelLTA() throws Exception {
        File sampleFile = new File(PathUtil.getAppHome(), "res/test/pdf/sample.pdf");
        LOG.debug("Tests signing of " + sampleFile.getName());

        ocspDataLoader.numberOfLookups = 0;
        assertSignPDF(sampleFile, LTA_WORKER_ID, true, true, true, false, true, true,
                      true);

        assertEquals("Number of OCSP lookups", 2 + 2, ocspDataLoader.numberOfLookups);
    }

    /**
     * Test sign and verify a sample PDF file using a level BASELINE-LTA signer
     * @throws Exception in case of test error
     */
    @Test
    public void testSignPDFLevelLTAwithCRL() throws Exception {
        File sampleFile = new File(PathUtil.getAppHome(), "res/test/pdf/sample.pdf");
        LOG.debug("Tests signing of " + sampleFile.getName());

        ocspDataLoader.numberOfLookups = 0;
        crlDataLoader.numberOfLookups = 0;
        final boolean expectCrl = true;
        assertSignPDF(sampleFile, LTA_CRL_WORKER_ID, true, true, true, expectCrl, true, true,
                      true);

        assertEquals("Number of CRL lookups", 2, ocspDataLoader.numberOfLookups);
        assertEquals("Number of OCSP lookups", 2, ocspDataLoader.numberOfLookups);
    }

    /**
     * Test sign and verify a sample PDF file using a level BASELINE-LTA signer with CRL and large signature.
     *
     * @throws Exception in case of test error
     */
    @Test
    public void testSignPDFLevelLTAWithCRLLargeSignature() throws Exception {
        File sampleFile = new File(PathUtil.getAppHome(), "res/test/pdf/sample.pdf");
        LOG.debug("Tests signing of " + sampleFile.getName() + " with a large signature");

        ocspDataLoader.numberOfLookups = 0;
        crlDataLoader.numberOfLookups = 0;
        final boolean expectCrl = true;
        assertSignPDF(sampleFile, LTA_CRL_EXTRA_SIGNATURE_SPACE_WORKER_ID, true, true, true, expectCrl, true, true,
                true);

        assertEquals("Number of CRL lookups", 2, ocspDataLoader.numberOfLookups);
        assertEquals("Number of OCSP lookups", 2, ocspDataLoader.numberOfLookups);
    }

    /**
     * Test sign and verify a sample PDF file using a level BASELINE-LT signer
     * @throws Exception in case of test error
     */
    @Test
    public void testSignPDFLevelLTOtherOCSP() throws Exception {
        File sampleFile = new File(PathUtil.getAppHome(), "res/test/pdf/sample.pdf");
        LOG.debug("Tests signing of " + sampleFile.getName());

        otherOcspDataLoader.numberOfLookups = 0;
        assertSignPDF(sampleFile, LT_ALT_OCSP_WORKER_ID, true, false, true, false,
                      true, true, false);

        assertEquals("Number of OCSP lookups", 2,
                     otherOcspDataLoader.numberOfLookups);
    }

    /**
     * Test sign and verify a sample PDF file using a level BASELINE-LT signer
     * @throws Exception in case of test error
     */
    @Test
    public void testSignPDFLevelLTOtherOCSPOtherTsa() throws Exception {
        File sampleFile = new File(PathUtil.getAppHome(), "res/test/pdf/sample.pdf");
        LOG.debug("Tests signing of " + sampleFile.getName());

        otherOcspDataLoader.numberOfLookups = 0;
        assertSignPDF(sampleFile, LT_ALT_OCSP_ALT_TSA_WORKER_ID, true, false,
                      true, false, true, true, false);

        assertEquals("Number of OCSP lookups", 2,
                     otherOcspDataLoader.numberOfLookups);
    }

    @Test
    public void testSignPDFLevelTUsingSub() throws Exception {
        File sampleFile = new File(PathUtil.getAppHome(), "res/test/pdf/sample.pdf");
        LOG.debug("Tests signing of " + sampleFile.getName());

        assertSignPDF(sampleFile, T_WORKER_ID, true, false, false, false, true, false,
                      false);
    }


    // TODO Implement
//    @Test
//    public void signXAdES() {
//        // given
//
//        // when
//
//        // then
//
//    }

    // Copied from the system test, TODO: refactor-out to a common module
    private void assertVerifiedCms(final CMSSignedData signedData,
                                   final SignatureAlgorithm expectedSigAlg,
                                   final String expectedSigOid,
                                   final Date expectedTimeStamp,
                                   final String expectedSignatureTimeStampDigestOid,
                                   final Date expectedContentTimeStamp,
                                   final String expectedContentTimeStampDigestOid,
                                   final Date expectedArchiveTimeStamp,
                                   final String expectedArchiveTimeStampDigestOid)
            throws OperatorCreationException, CertificateException,
                   CMSException, IOException, TSPException,
                   NoSuchAlgorithmException {

        //String expectedSigOid = expectedSigAlg.getOid();

        int verified = 0;

        Store                   certStore = signedData.getCertificates();
        SignerInformationStore  signers = signedData.getSignerInfos();
        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        boolean foundArchiveTimestamp = false;

        while (it.hasNext()) {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(signer.getSID());

            Iterator              certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals("expected signature " + expectedSigAlg, signer.getEncryptionAlgOID(), expectedSigOid);

            if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
                verified++;

                // Check signature time-stamp token
                if (expectedSignatureTimeStampDigestOid != null) {
                    final Attribute tsAttr = signer.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
                    assertNotNull("Unsigned attribute present", tsAttr);

                    final TimeStampToken tst = new TimeStampToken(new CMSSignedData(tsAttr.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
                    assertEquals("TST digest alg oid", expectedSignatureTimeStampDigestOid, tst.getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId());

                    if (expectedTimeStamp != null) {
                        assertEquals("Timestamp time equals", expectedTimeStamp,
                                     tst.getTimeStampInfo().getGenTime());
                    }

                    // Check that message imprint is digest of the signature value
                    byte[] expectedDigest = DigestAlgorithm.forOID(expectedSignatureTimeStampDigestOid).getMessageDigest().digest(signer.getSignature());
                    assertEquals("TST message imprint value", Hex.toHexString(expectedDigest), Hex.toHexString(tst.getTimeStampInfo().getMessageImprintDigest()));
                }

                // Check content time-stamp token
                if (expectedContentTimeStampDigestOid != null) {
                    final Attribute tsAttr = signer.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_contentTimestamp);
                    assertNotNull("Signed attribute present", tsAttr);

                    final TimeStampToken tst = new TimeStampToken(new CMSSignedData(tsAttr.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
                    assertEquals("TST digest alg oid", expectedContentTimeStampDigestOid, tst.getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId());

                    if (expectedContentTimeStamp != null) {
                        assertEquals("Timestamp time equals",
                                     expectedContentTimeStamp,
                                     tst.getTimeStampInfo().getGenTime());
                    }

                    // Check that message imprint is digest of the content value
                    final Attribute mdAttr = signer.getSignedAttributes().get(CMSAttributes.messageDigest);
                    final ASN1OctetString messageDigestObject = ASN1OctetString.getInstance(mdAttr.getAttrValues().getObjectAt(0).toASN1Primitive());

                    byte[] expectedDigest = messageDigestObject.getOctets();

                    assertEquals("TST message imprint value", Hex.toHexString(expectedDigest), Hex.toHexString(tst.getTimeStampInfo().getMessageImprintDigest()));
                }

                final Attribute archiveTsAttr = signer.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_archiveTimestamp);

                if (archiveTsAttr != null) {
                    final TimeStampToken tst = new TimeStampToken(new CMSSignedData(archiveTsAttr.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
                    assertEquals("TST digest alg oid", expectedArchiveTimeStampDigestOid, tst.getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId());

                    foundArchiveTimestamp = true;

                    if (expectedContentTimeStamp != null) {
                        assertEquals("Timestamp time equals",
                                     expectedContentTimeStamp,
                                     tst.getTimeStampInfo().getGenTime());
                    }

                    // Check that message imprint is digest of the content value
                    final Attribute mdAttr = signer.getSignedAttributes().get(CMSAttributes.messageDigest);
                    final ASN1OctetString messageDigestObject = ASN1OctetString.getInstance(mdAttr.getAttrValues().getObjectAt(0).toASN1Primitive());

                    byte[] expectedDigest = messageDigestObject.getOctets();

                    assertEquals("TST message imprint value", Hex.toHexString(expectedDigest), Hex.toHexString(tst.getTimeStampInfo().getMessageImprintDigest()));
                }
            }
        }

        assertEquals("Expected archive timestamp",
                     expectedArchiveTimeStamp != null,
                     foundArchiveTimestamp);
        assertTrue("verified", verified > 0);
    }
}
