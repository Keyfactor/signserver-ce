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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import junit.framework.TestCase;
import static junit.framework.TestCase.assertEquals;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.encoders.Base64;
import org.ejbca.util.CertTools;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.server.SignServerContext;
import org.signserver.server.ZeroTimeSource;
import org.signserver.server.cryptotokens.HardCodedCryptoToken;
import org.signserver.server.cryptotokens.HardCodedCryptoTokenAliases;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.log.LogMap;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.test.utils.builders.CryptoUtils;

import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.test.utils.mock.WorkerSessionMock;
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
public class MSAuthCodeTimeStampSignerTest extends TestCase {
    
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
     * @param requestData Request data to test with
     * @param includeSigningCertAttr If true, include and test the SigningCertificate attribute
     * @throws Exception
     */
    private void testProcessDataWithAlgo(final String signingAlgo, final String expectedDigestOID,
            final byte[] requestData, final boolean includeSigningCertAttr,
            final String includeCertificateLevels) throws Exception {
        SignServerUtil.installBCProvider();
        
        final String CRYPTOTOKEN_CLASSNAME =
                "org.signserver.server.cryptotokens.HardCodedCryptoToken";
        
        final ProcessRequest signRequest;
        
        final GlobalConfigurationSessionMock globalConfig
                = new GlobalConfigurationSessionMock();
        final WorkerSessionMock workerMock = new WorkerSessionMock(globalConfig);
        
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("NAME", "TestMSAuthCodeTimeStampSigner");
        config.setProperty("AUTHTYPE", "NOAUTH");
        config.setProperty("TIMESOURCE", "org.signserver.server.ZeroTimeSource");
        config.setProperty("SIGNATUREALGORITHM", signingAlgo);
        config.setProperty("DEFAULTKEY", HardCodedCryptoTokenAliases.KEY_ALIAS_1);
        
        if (includeSigningCertAttr) {
            config.setProperty("INCLUDE_SIGNING_CERTIFICATE_ATTRIBUTE", "true");
        }
        
        if (includeCertificateLevels != null) {
            config.setProperty(WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS,
                    includeCertificateLevels);
        }
        
        final MSAuthCodeTimeStampSigner worker = new MSAuthCodeTimeStampSigner() {
            @Override
            protected IGlobalConfigurationSession.IRemote
                    getGlobalConfigurationSession() {
                return globalConfig;
            }
        };
            
        workerMock.setupWorker(SIGNER_ID, CRYPTOTOKEN_CLASSNAME, config, worker);
        workerMock.reloadConfiguration(SIGNER_ID);
        
        // if the INCLUDE_CERTIFICATE_LEVELS property has been set,
        // check that it gives a not supported error
        if (includeCertificateLevels != null) {
            final List<String> errors = worker.getFatalErrors();
            
            assertTrue("Should contain config error",
                    errors.contains(WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS + " is not supported."));
            return;
        }
        
        // create sample hard-coded request
        signRequest = new GenericSignRequest(REQUEST_ID, requestData);

        final RequestContext requestContext = new RequestContext();
        GenericSignResponse resp = (GenericSignResponse) workerMock.process(SIGNER_ID, signRequest, requestContext);
        
        // check that the response contains the needed attributes
        byte[] buf = resp.getProcessedData();
        ASN1Sequence asn1seq = ASN1Sequence.getInstance(Base64.decode(buf));
        
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(asn1seq.getObjectAt(0));
        ASN1TaggedObject ato = ASN1TaggedObject.getInstance(asn1seq.getObjectAt(1));
        
        assertEquals("Invalid OID in response", SIGNED_DATA_OID, oid.getId());
        
        ASN1Sequence asn1seq1 = ASN1Sequence.getInstance(ato.getObject());

        ASN1Set asn1set = ASN1Set.getInstance(asn1seq1.getObjectAt(4));
        ASN1Sequence asn1seq2 = ASN1Sequence.getInstance(asn1set.getObjectAt(0));
        ASN1TaggedObject ato1 = ASN1TaggedObject.getInstance(asn1seq2.getObjectAt(3));
        ASN1Sequence asn1seq3 = ASN1Sequence.getInstance(ato1.getObject());
        ASN1Sequence asn1seq4 = ASN1Sequence.getInstance(asn1seq3.getObjectAt(0));
        ASN1Sequence asn1seq5 = ASN1Sequence.getInstance(asn1seq3.getObjectAt(1));
        ASN1Sequence asn1seq6 = ASN1Sequence.getInstance(asn1seq3.getObjectAt(2));
        
        final X509Certificate cert =
                (X509Certificate) CertTools.getCertfromByteArray(HardCodedCryptoToken.certbytes1);
        // expected serial number
        final BigInteger sn = cert.getSerialNumber();

        // if INCLUDE_SIGNING_CERTIFICATE_ATTRIBUTE is set to false, the attribute should not be included
        if (!includeSigningCertAttr) {
            assertEquals("Number of attributes", 3, asn1seq3.size());
        } else {
            final ASN1Sequence scAttr = ASN1Sequence.getInstance(asn1seq3.getObjectAt(3));
            TestUtils.checkSigningCertificateAttribute(scAttr, cert);
        }
        
        ASN1ObjectIdentifier ctOID = ASN1ObjectIdentifier.getInstance(asn1seq4.getObjectAt(0));
        assertEquals("Invalid OID for content type", CONTENT_TYPE_OID, ctOID.getId());
        
        ASN1ObjectIdentifier stOID = ASN1ObjectIdentifier.getInstance(asn1seq5.getObjectAt(0));
        assertEquals("Invalid OID for signing time", SIGNING_TIME_OID, stOID.getId());
        
        ASN1ObjectIdentifier mdOID = ASN1ObjectIdentifier.getInstance(asn1seq6.getObjectAt(0));
        assertEquals("Invalid OID for content type", MESSAGE_DIGEST_OID, mdOID.getId());
        
        // get signing time from response
        ASN1Set set = ASN1Set.getInstance(asn1seq5.getObjectAt(1));
        ASN1Encodable t = set.getObjectAt(0);
        Time t2 = Time.getInstance(t);
        Date d = t2.getDate();
        
        // the expected time (the "starting point" of time according to java.util.Date, consistent with the behavior of ZeroTimeSource
        Date d0 = new Date(0);
        
        assertEquals("Unexpected signing time in response", d0, d);	
    
    
        // check expected signing algo
        ASN1Set set1 = ASN1Set.getInstance(asn1seq1.getObjectAt(1));
        ASN1Sequence asn1seq7 = ASN1Sequence.getInstance(set1.getObjectAt(0));
        ASN1ObjectIdentifier algOid = ASN1ObjectIdentifier.getInstance(asn1seq7.getObjectAt(0));
        
        assertEquals("Unexpected digest OID in response", expectedDigestOID, algOid.getId());
        
        // check that the request is included
        final CMSSignedData signedData = new CMSSignedData(asn1seq.getEncoded());
        final byte[] content = (byte[]) signedData.getSignedContent()
                .getContent();
        
        final ASN1Sequence seq = ASN1Sequence.getInstance(Base64.decode(requestData));
        final ASN1Sequence seq2 = ASN1Sequence.getInstance(seq.getObjectAt(1));
        final ASN1TaggedObject tag = ASN1TaggedObject.getInstance(seq2.getObjectAt(1));
        final ASN1OctetString data = ASN1OctetString.getInstance(tag.getObject());

        assertTrue("Contains request data", Arrays.equals(data.getOctets(), content));
    
        // check the signing certificate
        final X509Certificate signercert = (X509Certificate) resp.getSignerCertificate();
        assertEquals("Serial number", sn, signercert.getSerialNumber());
        assertEquals("Issuer", cert.getIssuerDN(), signercert.getIssuerDN());
        
        // check ContentInfo, according to the Microsoft specification, the contentInfo in the response is
        // identical to the contentInfo in the request
        final ContentInfo expCi = new ContentInfo(seq2);
        final ContentInfo ci = new ContentInfo(ASN1Sequence.getInstance(asn1seq1.getObjectAt(2)));
        
        assertEquals("Content info should match the request", expCi, ci);
        
        // Get signers
        final Collection signers = signedData.getSignerInfos().getSigners();
        final SignerInformation signer
                = (SignerInformation) signers.iterator().next();

        // Verify using the signer's certificate
        assertTrue("Verification using signer certificate",
                signer.verify(signercert.getPublicKey(), "BC"));

        // Check that the time source is being logged
        LogMap logMap = LogMap.getInstance(requestContext);
        assertEquals("timesource", ZeroTimeSource.class.getSimpleName(), logMap.get("TSA_TIMESOURCE"));
        
        assertNotNull("response",
                logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPRESPONSE_ENCODED));
        assertEquals("log line doesn't contain newlines", -1,
                logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPRESPONSE_ENCODED).lastIndexOf('\n'));
    }
    
    /**
     * Test of processData method, of class MSAuthCodeTimeStampSigner.
     */
    public void testProcessDataSHA1withRSA() throws Exception {
    	testProcessDataWithAlgo("SHA1withRSA", SHA1_OID, REQUEST_DATA.getBytes(), false, null);
    }
    
    public void testProcessDataSHA256withRSA() throws Exception {
    	testProcessDataWithAlgo("SHA256withRSA", SHA256_OID, REQUEST_DATA.getBytes(), false, null);
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
     * Test with a null requestData. Shall give an IllegalRequestException.
     * @throws Exception
     */
    public void testNullRequest() throws Exception {
        try {
            testProcessDataWithAlgo("SHA1withRSA", SHA1_OID, null, false, null);
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
            certBuilder.addExtension(new CertExt(X509Extension.extendedKeyUsage, 
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
        
        final List<String> fatalErrors = instance.getFatalErrors();
        
        if (expectedFailure) {
            assertFalse("Should report fatal error", fatalErrors.isEmpty());
        }
        
        if (expectedErrorMessage != null && !expectedErrorMessage.isEmpty()) {
            assertTrue("Should contain error: " + fatalErrors,
                       fatalErrors.contains(expectedErrorMessage));
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
        public Certificate getSigningCertificate(final ProcessRequest request,
                                                 final RequestContext context)
                throws CryptoTokenOfflineException {
            return mockedToken.getCertificate(ICryptoToken.PURPOSE_SIGN);
        }

        @Override
        public List<Certificate> getSigningCertificateChain(
                final ProcessRequest request, final RequestContext context)
                throws CryptoTokenOfflineException {
            return mockedToken.getCertificateChain(ICryptoToken.PURPOSE_SIGN);
        }

        @Override
        public ICryptoToken getCryptoToken() {
            return mockedToken;
        }
    }
}
