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
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static junit.framework.TestCase.assertEquals;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.server.IServices;
import org.signserver.server.SignServerContext;
import org.signserver.server.ZeroTimeSource;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.log.LogMap;
import org.signserver.test.utils.CertTools;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.test.utils.builders.CryptoUtils;

import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.test.utils.mock.MockedRequestContext;
import org.signserver.test.utils.mock.MockedServicesImpl;
import org.signserver.test.utils.mock.WorkerSessionMock;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestUtils;

/**
 * 
 * Unit test testing the functionallity of the MSAuthCodeTimeStampSigner by
 * using a prerecorded request from the "signtool" CLI tool from Microsoft's SDK.
 * The tests checks that the response contains the right content type, timestamp is correctly set 
 * and uses the signature algorithm as set.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class MSAuthCodeTimeStampSignerTest extends ModulesTestCase {
    
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(MSAuthCodeTimeStampSignerTest.class);
    
    private static int SIGNER_ID = 1000;
    private static int REQUEST_ID = 42;
    private static final String REQUEST_DATA =
    		"MIIBIwYKKwYBBAGCNwMCATCCARMGCSqGSIb3DQEHAaCCAQQEggEAVVSpOKf9zJYc" +
    		"tyvqgeHfO9JkobPYihUZcW9TbYzAUiJGEsElNCnLUaO0+MZG0TS7hlzqKKvrdXc7" +
    		"O/8C7c8YyjYF5YrLiaYS8cw3VbaQ2M1NWsLGzxF1pxsR9sMDJvfrryPaWj4eTi3Y" +
    		"UqRNS+GTa4quX4xbmB0KqMpCtrvuk4S9cgaJGwxmSE7N3omzvERTUxp7nVSHtms5" +
    		"lVMb082JFlABT1/o2mL5O6qFG119JeuS1+ZiL1AEy//gRs556OE1TB9UEQU2bFUm" +
    		"zBD4VHvkOOB/7X944v9lmK5y9sFv+vnf/34catL1A+ZNLwtd1Qq2VirqJxRK/T61" +
    		"QoSWj4rGpw==";
    
    private static final String SIGNED_DATA_OID = "1.2.840.113549.1.7.2";
    private static final String CONTENT_TYPE_OID = "1.2.840.113549.1.9.3";
    private static final String SIGNING_TIME_OID = "1.2.840.113549.1.9.5";
    private static final String MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4";
    private static final String SHA1_OID = "1.3.14.3.2.26";
    private static final String SHA256_OID = "2.16.840.1.101.3.4.2.1";
    private static final String SIGNING_CERT_OID = "1.2.840.113549.1.9.16.2.12";

    private static byte[] certbytes1 = Base64.decode((
            "MIIEkTCCAnmgAwIBAgIIeCvAS5OwAJswDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJv"
            + "b3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYT"
            + "AlNFMB4XDTExMDUyNzEyMTU1NVoXDTIxMDUyNDEyMTU1NVowSjEUMBIGA1UEAwwLVFMgU2lnbmVy"
            + "IDExEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIB"
            + "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnT38GG8i/bGnuFMwnOdg+caHMkdPBacRdBaI"
            + "ggwMPfE50SOZ2TLrDEHJotxYda7HS0+tX5dIcalmEYCls/ptHzO5TQpqdRTuTqxp5cMA379yhD0O"
            + "qTVNAmHrvPj9IytktoAtB/xcjwkRTHagaCmg5SWNcLKyVUct7nbeRA5yDSJQsCAEGHNZbJ50vATg"
            + "1DQEyKT87GKfSBsclA0WIIIHMt8/SRhpsUZxESayU6YA4KCxVtexF5x+COLB6CzzlRG9JA8WpX9y"
            + "KgIMsMDAscsJLiLPjhET5hwAFm5ZRfQQG9LI06QNTGqukuTlDbYrQGAUR5ZXW00WNHfgS00CjUCu"
            + "0QIDAQABo3gwdjAdBgNVHQ4EFgQUOF0FflO2G+IN6c92pCNlPoorGVwwDAYDVR0TAQH/BAIwADAf"
            + "BgNVHSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/"
            + "BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBADELkeIO9aiKjS/GaBUUhMr+k5UbVeK6"
            + "9WapU+7gTsWwa9D2vAOhAkfQ1OcUJoZaminv8pcNfo1Ey5qLtxBCmUy1fVomVWOPl6u1w8B6uYgE"
            + "608hi2bfx28uIeksqpdqUX0Qf6ReUyl+FOh4xNrsyaF81TrIKt8ekq0iD+YAtT/jqgv4bUvs5fgI"
            + "ms4QOXgMUzNAP7cPU44KxcmR5I5Uy/Ag82hGIz64hZmeIDT0X59kbQvlZqFaiZvYOikoZSFvdM5k"
            + "SVfItMgp7qmyLxuM/WaXqJWp6Mm+8ZZmcECugd4AEpE7xIiB7M/KEe+X4ItBNTKdAoaxWa+yeuYS"
            + "7ol9rHt+Nogelj/06ZRQ0x03UqC7uKpgYAICjQEXIjcZofWSTh9KzKNfS1sQyIQ6yNTT2VMdYW9J"
            + "C2OLKPV4AEJuBw30X8HOciJRRXOq9KRrIA2RSiaC5/3oAYscWuo31Fmj8CWQknXAIb39gPuZRwGO"
            + "Jbi1tUu2zmRsUNJfAe3hnvk+uxhnyp2vKB2KN5/VQgisx+8doEK/+Nbj/PPG/zASKimWG++5m0JN"
            + "Y4chIfR43gDDcF+4INof/8V84wbvUF+TpvP/mYM8wC9OkUyRvzqv9vjWOncCdbdjCuqPxDItwm9h"
            + "hr+PbxsMaBes9rAiV9YT1FnpA++YpCufveFCQPDbCTgJ").getBytes());
    
    private static final String KEY_ALIAS_1 = "TS Signer 1";
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }
    
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }


    /**
     * Performs test using specified signature algorithm, digest algorithm and with the optional SigningCertificate attribute included or not included.
     * 
     * The SigningCertificate attribute is specified in RFC 2634.
     * 
     * SigningCertificate ::=  SEQUENCE {
     *  certs        SEQUENCE OF ESSCertID,
     *  policies     SEQUENCE OF PolicyInformation OPTIONAL
     * }
     *
     * id-aa-signingCertificate OBJECT IDENTIFIER ::= { iso(1)
     *  member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
     *  smime(16) id-aa(2) 12 }
     *
     * ESSCertID ::=  SEQUENCE {
     *   certHash                 Hash,
     *   issuerSerial             IssuerSerial OPTIONAL
     * }
     * Hash ::= OCTET STRING -- SHA1 hash of entire certificate
     *
     * IssuerSerial ::= SEQUENCE {
     *   issuer                   GeneralNames,
     *   serialNumber             CertificateSerialNumber
     * }
     * 
     * @param signingAlgo Signature algorithm to use
     * @param expectedDigestOID Expected digest OID
     * @param data Request data to test with
     * @param includeSigningCertAttr If true, include and test the SigningCertificate attribute
     * @throws Exception
     */
    private void testProcessDataWithAlgo(final String signingAlgo, final String expectedDigestOID,
            final byte[] data, final boolean includeSigningCertAttr,
            final String includeCertificateLevels) throws Exception {
        SignServerUtil.installBCProvider();
        
        final String CRYPTOTOKEN_CLASSNAME =
                "org.signserver.server.cryptotokens.KeystoreCryptoToken";

        final GlobalConfigurationSessionMock globalConfig
                = new GlobalConfigurationSessionMock();
        final WorkerSessionMock workerMock = new WorkerSessionMock();
        final IServices services = new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, globalConfig);
        
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("NAME", "TestMSAuthCodeTimeStampSigner");
        config.setProperty("AUTHTYPE", "NOAUTH");
        config.setProperty("TIMESOURCE", "org.signserver.server.ZeroTimeSource");
        config.setProperty("SIGNATUREALGORITHM", signingAlgo);
        config.setProperty("DEFAULTKEY", KEY_ALIAS_1);
        config.setProperty("KEYSTOREPATH",
                getSignServerHome() + File.separator + "res" +
                        File.separator + "test" + File.separator + "dss10" +
                        File.separator + "dss10_tssigner1.p12");
        config.setProperty("KEYSTORETYPE", "PKCS12");
        config.setProperty("KEYSTOREPASSWORD", "foo123");
        
        if (includeSigningCertAttr) {
            config.setProperty("INCLUDE_SIGNING_CERTIFICATE_ATTRIBUTE", "true");
        }
        
        if (includeCertificateLevels != null) {
            config.setProperty(WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS,
                    includeCertificateLevels);
        }
        
        final MSAuthCodeTimeStampSigner worker = new MSAuthCodeTimeStampSigner();
            
        workerMock.setupWorker(SIGNER_ID, CRYPTOTOKEN_CLASSNAME, config, worker);
        workerMock.reloadConfiguration(SIGNER_ID);
        
        // if the INCLUDE_CERTIFICATE_LEVELS property has been set,
        // check that it gives a not supported error
        if (includeCertificateLevels != null) {
            final List<String> errors = worker.getFatalErrors(services);
            
            assertTrue("Should contain config error",
                    errors.contains(WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS + " is not supported."));
            return;
        }

        SignatureResponse resp;
        byte[] buf;        
        try (
                CloseableReadableData requestData = createRequestData(data);
                CloseableWritableData responseData = createResponseData(false);
            ) {   
            // create sample hard-coded request
            SignatureRequest signRequest = new SignatureRequest(REQUEST_ID, requestData, responseData);

            resp = (SignatureResponse) workerMock.process(new AdminInfo("Client user", null, null), new WorkerIdentifier(SIGNER_ID), signRequest, new MockedRequestContext(services));

            // check that the response contains the needed attributes
            buf = responseData.toReadableData().getAsByteArray();
        }
        ASN1Sequence asn1seq = ASN1Sequence.getInstance(Base64.decode(buf));
        CMSSignedData signedData = new CMSSignedData(asn1seq.getEncoded());
        ASN1TaggedObject ato = ASN1TaggedObject.getInstance(asn1seq.getObjectAt(1));
        ASN1Sequence asn1seq1 = ASN1Sequence.getInstance(ato.getObject());
        final X509Certificate cert =
                (X509Certificate) CertTools.getCertfromByteArray(certbytes1);
        // expected serial number
        final BigInteger sn = cert.getSerialNumber();

        // if INCLUDE_SIGNING_CERTIFICATE_ATTRIBUTE is set to false, the attribute should not be included       
        final SignerInformationStore signerInfos = signedData.getSignerInfos();
        final SignerInformation si = signerInfos.getSigners().iterator().next();
        final AttributeTable signedAttributes = si.getSignedAttributes();
        final Attribute signingCertAttr =
                signedAttributes.get(new ASN1ObjectIdentifier(SIGNING_CERT_OID));
        
        if (!includeSigningCertAttr) {
            assertNull("No signing cert attribute", signingCertAttr);
        } else {
            TestUtils.checkSigningCertificateAttribute(signingCertAttr, cert,
                                                       "SHA1", false);
        }
        
        final Attribute contentTypeAttr =
                signedAttributes.get(new ASN1ObjectIdentifier(CONTENT_TYPE_OID));
        assertNotNull("Content type attribute", contentTypeAttr);
        
        final Attribute signingTimeAttr =
                signedAttributes.get(new ASN1ObjectIdentifier(SIGNING_TIME_OID));
        assertNotNull("Signing time attribute", signingTimeAttr);
        
        final Attribute messageDigestAttr =
                signedAttributes.get(new ASN1ObjectIdentifier(MESSAGE_DIGEST_OID));
        assertNotNull("Message digest attribute", messageDigestAttr);

        // get signing time from response
        final ASN1Encodable t = signingTimeAttr.getAttrValues().getObjectAt(0);
        Time t2 = Time.getInstance(t);
        Date d = t2.getDate();
        
        // the expected time (the "starting point" of time according to java.util.Date, consistent with the behavior of ZeroTimeSource
        Date d0 = new Date(0);
        
        assertEquals("Unexpected signing time in response", d0, d);	
    
        final AlgorithmIdentifier digAlg =
                signedData.getDigestAlgorithmIDs().iterator().next();
    
        // check expected signing algo
        assertEquals("Unexpected digest OID in response", expectedDigestOID, digAlg.getAlgorithm().getId());
        
        // check that the request is included
        final byte[] content = (byte[]) signedData.getSignedContent()
                .getContent();
        
        final ASN1Sequence seq = ASN1Sequence.getInstance(Base64.decode(data));
        final ASN1Sequence seq2 = ASN1Sequence.getInstance(seq.getObjectAt(1));
        final ASN1TaggedObject tag = ASN1TaggedObject.getInstance(seq2.getObjectAt(1));
        final ASN1OctetString octets = ASN1OctetString.getInstance(tag.getObject());

        assertTrue("Contains request data", Arrays.equals(octets.getOctets(), content));
    
        // check the signing certificate
        final X509Certificate signercert = (X509Certificate) resp.getSignerCertificate();
        assertEquals("Serial number", sn, signercert.getSerialNumber());
        assertEquals("Issuer", cert.getIssuerDN(), signercert.getIssuerDN());

        // check ContentInfo, according to the Microsoft specification, the contentInfo in the response is
        // identical to the contentInfo in the request
        final ContentInfo expCi = ContentInfo.getInstance(seq2);
        final ContentInfo ci = ContentInfo.getInstance(ASN1Sequence.getInstance(asn1seq1.getObjectAt(2)));
        
        assertEquals("Content info should match the request", expCi, ci);
        
        // Get signers
        final Collection signers = signedData.getSignerInfos().getSigners();
        final SignerInformation signer
                = (SignerInformation) signers.iterator().next();

        // Verify using the signer's certificate
        final SignerInformationVerifier verifier =
            new JcaSignerInfoVerifierBuilder(new JcaDigestCalculatorProviderBuilder().build()).setProvider("BC").build(signercert.getPublicKey());
        assertTrue("Verification using signer certificate", signer.verify(verifier));

        // Check that the time source is being logged
        final LogMap logMap = LogMap.getInstance(workerMock.getLastRequestContext());
        final Object timeSourceLoggable = logMap.get("TSA_TIMESOURCE");
        assertEquals("timesource", ZeroTimeSource.class.getSimpleName(),
                     String.valueOf(timeSourceLoggable));
        
        assertNotNull("response",
                logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPRESPONSE_ENCODED));
        final Object loggable =
                logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPRESPONSE_ENCODED);
        assertEquals("log line doesn't contain newlines", -1,
                String.valueOf(loggable).lastIndexOf('\n'));
    }
    
    /**
     * Test of processData method, of class MSAuthCodeTimeStampSigner.
     * @throws java.lang.Exception
     */
    public void testProcessDataSHA1withRSA() throws Exception {
    	testProcessDataWithAlgo("SHA1withRSA", SHA1_OID, REQUEST_DATA.getBytes(), false, null);
    }
    
    public void testProcessDataSHA256withRSA() throws Exception {
    	testProcessDataWithAlgo("SHA256withRSA", SHA256_OID, REQUEST_DATA.getBytes(), false, null);
    }
    
    public void testProcessDataWithDefaultSignatureAlgorithm() throws Exception {
        testProcessDataWithAlgo("  ", SHA256_OID, REQUEST_DATA.getBytes(), false, null);
    }
    
    /**
     * Test with requestData with zero length. Shall give an IllegalRequestException.
     * @throws Exception
     */
    public void testEmptyRequest() throws Exception {
        try {
            testProcessDataWithAlgo("SHA1withRSA", SHA1_OID, new byte[0], false, null);
        } catch (IllegalRequestException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e.getClass().getName());
        }
    }
    
    /**
     * Test with an invalid requestData. Shall give an IllegalRequestException.
     * @throws Exception
     */
    public void testBogusRequest() throws Exception {
        try {
            testProcessDataWithAlgo("SHA1withRSA", SHA1_OID, "bogus request".getBytes(), false, null);
        } catch (IllegalRequestException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e.getClass().getName());
        }
    }
    
    /**
     * Test with the signingCertificate attribute included.
     * 
     * @throws Exception
     */
    public void testIncludeSigningCertificateAttribute() throws Exception {
        testProcessDataWithAlgo("SHA1withRSA", SHA1_OID, REQUEST_DATA.getBytes(), true, null);
    }
    
    /**
     * Test that setting INCLUDE_CERTIFICATE_LEVELS gives
     * a config error, as this is not supported by this
     * signer.
     * 
     * @throws Exception
     */
    public void test0IncludeCertificateLevelsNotPermitted() throws Exception {
        testProcessDataWithAlgo("SHA1withRSA", SHA1_OID, null, false, "2");
    }
    
    /**
     * Test that setting a signer certificate with no extended key usage
     * results in a configuration error.
     * 
     * @throws Exception 
     */
    public void testWithNoEKU() throws Exception {
        testWithEKUs(null, false, true, "Missing extended key usage timeStamping");
    }
    
    /**
     * Test that setting a signer certificate with extended key usage
     * timeStamping set as non-critical results in a configuration error.
     * 
     * @throws Exception 
     */
    public void testWithTimestampingEKUNoCritical() throws Exception {
        testWithEKUs(new KeyPurposeId[] {KeyPurposeId.id_kp_timeStamping},
                     false, true,
                     "The extended key usage extension must be present and marked as critical");
    }
    
    /**
     * Test that setting a signer certificate with extended key usage
     * timeStamping set as critical results in no configuration error.
     * 
     * @throws Exception 
     */
    public void testWithTimestampingEKUCritical() throws Exception {
        testWithEKUs(new KeyPurposeId[] {KeyPurposeId.id_kp_timeStamping},
                     true, false, null);
    }
    
    /**
     * Test that setting a signer certificate with additional extended key usage
     * in addition to timeStaming results in a configuration error.
     * 
     * @throws Exception 
     */
    public void testWithAdditionalEKU() throws Exception {
       testWithEKUs(new KeyPurposeId[] {KeyPurposeId.id_kp_timeStamping,
                                        KeyPurposeId.id_kp_emailProtection},
                    true, true,
                    "No other extended key usages than timeStamping is allowed");
    }
    
    /**
     * Tests for the certificate requirements.
     *
     * @throws Exception 
     */
    @Test
    public void testCertificateIssues() throws Exception {
        LOG.info(">testCertificateIssues");

        MSAuthCodeTimeStampSigner instance = new MSAuthCodeTimeStampSigner();

        // Certifiate without id_kp_timeStamping
        final Certificate certNoEku = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=Without EKU").build());
        assertEquals(Arrays.asList("Missing extended key usage timeStamping", "The extended key usage extension must be present and marked as critical"), instance.getCertificateIssues(Arrays.asList(certNoEku)));
        
        // Certificate with non-critical id_kp_timeStamping
        boolean critical = false;
        final Certificate certEku = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=With non-critical EKU").addExtension(new CertExt(Extension.extendedKeyUsage, critical, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping))).build());
        assertEquals(Arrays.asList("The extended key usage extension must be present and marked as critical"), instance.getCertificateIssues(Arrays.asList(certEku)));
        
        // Certificate with critical id_kp_timeStamping but also with codeSigning
        critical = true;
        final Certificate certCritEkuButAlsoOther = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=With critical EKU and other").addExtension(new CertExt(Extension.extendedKeyUsage, critical, new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId.id_kp_timeStamping, KeyPurposeId.id_kp_codeSigning }))).build());
        assertEquals(Arrays.asList("No other extended key usages than timeStamping is allowed"), instance.getCertificateIssues(Arrays.asList(certCritEkuButAlsoOther)));
        
        // OK: Certificate with critical id_kp_timeStamping
        critical = true;
        final Certificate certCritEku = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=With critical EKU").addExtension(new CertExt(Extension.extendedKeyUsage, critical, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping))).build());
        assertEquals(Collections.<String>emptyList(), instance.getCertificateIssues(Arrays.asList(certCritEku)));
        
    }
    
    /**
     * Internal helper method setting up a mocked signer with configurable
     * signer certificate extended key usages and expected fatal errors.
     * 
     * @param ekus Array of extended keyusages, null if no extended key usage should be set
     * @param critical True if the extended key usage should be marked as critical
     * @param expectedFailure True if fatal errors is expected to contain errors
     * @param expectedErrorMessage Error message expected in the list of fatal
     *                             error, if null or empty, don't check error message
     * @throws Exception 
     */
    private void testWithEKUs(final KeyPurposeId[] ekus,
            final boolean critical, final boolean expectedFailure,
            final String expectedErrorMessage) throws Exception {
        final KeyPair signerKeyPair = CryptoUtils.generateRSA(1024);
        final String signatureAlgorithm = "SHA1withRSA";
        final CertBuilder certBuilder =
                new CertBuilder().
                        setSelfSignKeyPair(signerKeyPair).
                        setNotBefore(new Date()).
                        setSignatureAlgorithm(signatureAlgorithm);
                
        if (ekus != null && ekus.length > 0) {
            certBuilder.addExtension(new CertExt(Extension.extendedKeyUsage, 
                                                 critical,
                                                 new ExtendedKeyUsage(ekus)));
        }
            
        final Certificate[] certChain =
                new Certificate[] {new JcaX509CertificateConverter().getCertificate(
                        certBuilder.build())};
        final Certificate signerCertificate = certChain[0];
        final MockedCryptoToken token =
                new MockedCryptoToken(signerKeyPair.getPrivate(),
                                      signerKeyPair.getPublic(), 
                                      signerCertificate,
                                      Arrays.asList(certChain), "BC");
        
        final MSAuthCodeTimeStampSigner instance =
                new MockedMSAuthCodeTimeStampSigner(token);

        instance.init(1, new WorkerConfig(), new SignServerContext(), null);
        
        final List<String> fatalErrors = instance.getFatalErrors(null);
        
        if (expectedFailure) {
            assertFalse("Should report fatal error", fatalErrors.isEmpty());
        }
        
        if (expectedErrorMessage != null && !expectedErrorMessage.isEmpty()) {
            assertTrue("Should contain error: " + fatalErrors,
                       fatalErrors.contains(expectedErrorMessage));
        }
    }
    
    /**
     * Signer parameters when specified empty should work fine.
     * @throws Exception
     */
    @Test
    public void testWithEmptyParams() throws Exception {

        final KeyPair signerKeyPair = CryptoUtils.generateRSA(1024);
        final String signatureAlgorithm = "SHA1withRSA";
        final CertBuilder certBuilder
                = new CertBuilder().
                        setSelfSignKeyPair(signerKeyPair).
                        setNotBefore(new Date()).
                        setSignatureAlgorithm(signatureAlgorithm);
        KeyPurposeId[] ekus = new KeyPurposeId[]{KeyPurposeId.id_kp_timeStamping};
        if (ekus != null && ekus.length > 0) {
            certBuilder.addExtension(new CertExt(Extension.extendedKeyUsage,
                    true,
                    new ExtendedKeyUsage(ekus)));
        }
        final Certificate[] certChain
                = new Certificate[]{new JcaX509CertificateConverter().getCertificate(
                            certBuilder.build())};
        final Certificate signerCertificate = certChain[0];
        final MockedCryptoToken token
                = new MockedCryptoToken(signerKeyPair.getPrivate(),
                        signerKeyPair.getPublic(),
                        signerCertificate,
                        Arrays.asList(certChain), "BC");

        final MSAuthCodeTimeStampSigner instance
                = new MockedMSAuthCodeTimeStampSigner(token);

        WorkerConfig workerConfig = new WorkerConfig();

        workerConfig.setProperty("TIMESOURCE", "   ");
        workerConfig.setProperty("TYPE", "PROCESSABLE");
        workerConfig.setProperty("SIGNATUREALGORITHM", " ");

        instance.init(2, workerConfig, new SignServerContext(), null);

        final List<String> fatalErrors = instance.getFatalErrors(null);

        assertTrue("Should not report fatal error" + fatalErrors, fatalErrors.isEmpty());
    }      
    
    /**
     * Tests that Signer refuses to sign if worker has configuration errors.
     * @throws Exception
     */
    @Test
    public void testNoSigningWhenWorkerMisconfigued() throws Exception {
        SignServerUtil.installBCProvider();

        final String CRYPTOTOKEN_CLASSNAME
                = "org.signserver.server.cryptotokens.KeystoreCryptoToken";

        final GlobalConfigurationSessionMock globalConfig
                = new GlobalConfigurationSessionMock();
        final WorkerSessionMock workerMock = new WorkerSessionMock();
        final IServices services = new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, globalConfig);

        final WorkerConfig config = new WorkerConfig();
        config.setProperty("NAME", "TestMSAuthCodeTimeStampSigner");
        config.setProperty("AUTHTYPE", "NOAUTH");
        config.setProperty("TIMESOURCE", "org.signserver.server.ZeroTimeSource");
        config.setProperty("SIGNATUREALGORITHM", "   ");
        config.setProperty("INCLUDE_CERTIFICATE_LEVELS", "3");
        config.setProperty("DEFAULTKEY", KEY_ALIAS_1);
        config.setProperty("KEYSTOREPATH",
                getSignServerHome() + File.separator + "res"
                + File.separator + "test" + File.separator + "dss10"
                + File.separator + "dss10_tssigner1.p12");
        config.setProperty("KEYSTORETYPE", "PKCS12");
        config.setProperty("KEYSTOREPASSWORD", "foo123");

        final MSAuthCodeTimeStampSigner worker = new MSAuthCodeTimeStampSigner();

        workerMock.setupWorker(SIGNER_ID, CRYPTOTOKEN_CLASSNAME, config, worker);
        workerMock.reloadConfiguration(SIGNER_ID);        
        assertFalse("There should be config error ", worker.getFatalErrors(services).isEmpty());

        SignatureResponse resp;
        final byte[] data = REQUEST_DATA.getBytes();
        try (
                CloseableReadableData requestData = createRequestData(data);
                CloseableWritableData responseData = createResponseData(false);) {
            // create sample hard-coded request
            SignatureRequest signRequest = new SignatureRequest(REQUEST_ID, requestData, responseData);

            resp = (SignatureResponse) workerMock.process(new AdminInfo("Client user", null, null), new WorkerIdentifier(SIGNER_ID), signRequest, new MockedRequestContext(services));
        } catch (SignServerException expected) {
            assertEquals("exception message", "Worker is misconfigured", expected.getMessage());
        }
    }      
    
    /**
     * Mocked signer using a mocked crypto token.
     * 
     */
    private static class MockedMSAuthCodeTimeStampSigner
        extends MSAuthCodeTimeStampSigner {
        private final MockedCryptoToken mockedToken;
        
        /**
         * Create a mocked signer using the provided mocked token.
         * 
         * @param mockedToken 
         */
        public MockedMSAuthCodeTimeStampSigner(final MockedCryptoToken mockedToken) {
            this.mockedToken = mockedToken;
        }

        @Override
        public ICryptoTokenV4 getCryptoToken(final IServices services) {
            return mockedToken;
        }
    }
}
