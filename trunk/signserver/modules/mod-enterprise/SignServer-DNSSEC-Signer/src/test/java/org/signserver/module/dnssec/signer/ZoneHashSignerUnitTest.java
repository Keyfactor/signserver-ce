/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.dnssec.signer;

import java.net.InetAddress;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.jitsi.dnssec.SecurityStatus;
import org.jitsi.dnssec.validator.DnsSecVerifier;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.module.dnssec.common.ZoneHelper;
import org.signserver.server.IServices;
import org.signserver.server.SignServerContext;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.testutils.ModulesTestCase;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;

/**
 * Unit tests for the ZoneConstants class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ZoneHashSignerUnitTest {
       /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ZoneHashSignerUnitTest.class);

    private static MockedCryptoToken tokenRSA;

    private static final int WORKER = 42;

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        final KeyPair signerKeyPair;
        final String signatureAlgorithm;
        signerKeyPair = CryptoUtils.generateRSA(1024);
        signatureAlgorithm = "SHA256withRSA";
        final Certificate[] certChain =
                new Certificate[] {new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSelfSignKeyPair(signerKeyPair).
                        setNotBefore(new Date()).
                        setSignatureAlgorithm(signatureAlgorithm)
                        .build())};
        final Certificate signerCertificate = certChain[0];
        tokenRSA = new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), "BC");
    }

    /**
     * Test that leaving out required worker properties results in configuration
     * errors mentioning those properties.
     *
     * @throws Exception 
     */
    @Test
    public void testMissingRequiredProperties() throws Exception {
        final ZoneHashSigner instance = new ZoneHashSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };

        instance.init(WORKER, new WorkerConfig(), null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);

        assertTrue("contains error about missing ZSK_KEY_ALIAS_PREFIX",
                   fatalErrors.contains("Missing ZSK_KEY_ALIAS_PREFIX property"));
        assertTrue("contains error about missing ACTIVE_KSKS",
                   fatalErrors.contains("Missing ACTIVE_KSKS"));
    }

    /**
     * Test that more than 2 active KSKs are not accepted.
     * 
     * @throws Exception 
     */
    @Test
    public void testTooManyKsks() throws Exception {
        final ZoneHashSigner instance = new ZoneHashSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };

        final WorkerConfig config = new WorkerConfig();

        config.setProperty("ACTIVE_KSKS", "key1,key2,key3");
        instance.init(WORKER, config, null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);

        assertTrue("contains error about wrong number of KSKs",
                   fatalErrors.contains("Must specify exactly 1 or 2 active KSKs"));
    }

    /**
     * Test that DISABLEKEYUSAGECOUNTER as FALSE not allowed.
     *
     * @throws Exception
     */
    @Test
    public void testKeyUsageCounterDisabledFalse_ReportError() throws Exception {
        final ZoneHashSigner instance = new ZoneHashSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };

        final WorkerConfig config = new WorkerConfig();

        config.setProperty("DISABLEKEYUSAGECOUNTER", "false");
        instance.init(WORKER, config, null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);

        assertTrue("contains error about DISABLEKEYUSAGECOUNTER",
                fatalErrors.contains("DISABLEKEYUSAGECOUNTER must be TRUE for this signer"));
    }

    /**
     * Test that an empty list of KSKs is not accepted.
     * Should be treated as if ACTIVE_KSKS is not set.
     * 
     * @throws Exception 
     */
    @Test
    public void testTooFewKsks() throws Exception {
        final ZoneHashSigner instance = new ZoneHashSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };

        final WorkerConfig config = new WorkerConfig();

        config.setProperty("ACTIVE_KSKS", "");
        instance.init(WORKER, config, null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);

        assertTrue("contains error about missing ACTIVE_KSKS",
                   fatalErrors.contains("Missing ACTIVE_KSKS"));
    }

    /**
     * Test that setting a list of KSKs with extra whitespace gets trimmed
     * correctly.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrimKsks() throws Exception {
        final ZoneHashSigner instance = new ZoneHashSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };

        final WorkerConfig config = new WorkerConfig();

        config.setProperty("ACTIVE_KSKS", " key1 , key2");
        config.setProperty("ZSK_KEY_ALIAS_PREFIX", "example.com_Z_");
        config.setProperty("ZONE_NAME", "example.com.");
        config.setProperty("TYPE", "PROCESSABLE");
        instance.init(WORKER, config, null, null);

        final List<String> activeKsks = instance.activeKskAliases;

        assertEquals("number of active KSKs", 2, activeKsks.size());
        assertEquals("contains expected key", "key1", activeKsks.get(0));
        assertEquals("contains expected key", "key2", activeKsks.get(1));
    }

    /**
     * Test that setting a malformed NSEC3_SALT results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalNsec3Salt() throws Exception {
        final ZoneHashSigner instance = new ZoneHashSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };

        final WorkerConfig config = new WorkerConfig();

        config.setProperty("ACTIVE_KSKS", " key1 , key2");
        config.setProperty("ZSK_KEY_ALIAS_PREFIX", "example.com_Z_");
        config.setProperty("ZONE_NAME", "example.com.");
        config.setProperty("NSEC3_SALT", "_foobar");
        config.setProperty("TYPE", "PROCESSABLE");
        instance.init(WORKER, config, null, null);

        
        final String fatalErrors = instance.getFatalErrors(null).toString();

        assertTrue("contains error about malformed salt: " + fatalErrors,
                   fatalErrors.contains("Malformed NSEC3_SALT"));
        
    }

    /**
     * Test that setting a valid NSEC3_SALT results in no error.
     * 
     * @throws Exception 
     */
    @Test
    public void testCorrectNsec3Salt() throws Exception {
        final ZoneHashSigner instance = new ZoneHashSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };

        final WorkerConfig config = new WorkerConfig();

        config.setProperty("ACTIVE_KSKS", " key1 , key2");
        config.setProperty("ZSK_KEY_ALIAS_PREFIX", "example.com_Z_");
        config.setProperty("ZONE_NAME", "example.com.");
        config.setProperty("NSEC3_SALT", "12345678abcdef01");
        config.setProperty("TYPE", "PROCESSABLE");
        instance.init(WORKER, config, null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);
        
        assertFalse("no fatal errors", fatalErrors.toString().contains("Malformed NSEC3_SALT:"));
    }

    /**
     * Test that setting SIGNATUREALGORITHM SHA1withRSA works.
     * 
     * @throws Exception 
     */
    @Test
    public void testWithSignatureAlgorithmSHA1withRSA() throws Exception {
        internalTestWithSignatureAlgorithm("SHA1withRSA", false);
    }

    /**
     * Test that setting SIGNATUREALGORITHM SHA256withRSA works.
     * 
     * @throws Exception 
     */
    @Test
    public void testWithSignatureAlgorithmSHA256withRSA() throws Exception {
        internalTestWithSignatureAlgorithm("SHA256withRSA", false);
    }

    /**
     * Test that setting SIGNATUREALGORITHM SHA512withRSA works.
     * 
     * @throws Exception 
     */
    @Test
    public void testWithSignatureAlgorithmSHA512withRSA() throws Exception {
        internalTestWithSignatureAlgorithm("SHA512withRSA", false);
    }

    /**
     * Test that SIGNATUREALGORITHM SHA256withDSA is not supported.
     *
     * @throws Exception 
     */
    @Test
    public void testWithSignatureAlgorithmSHA256withDSANotSupported() throws Exception {
        internalTestWithSignatureAlgorithm("SHA256withDSA", true);
    }

    /**
     * Test that SIGNATUREALGORITHM SHA256withECDSA is not supported.
     *
     * @throws Exception 
     */
    @Test
    public void testWithSignatureAlgorithmSHA256withECDSANotSupported() throws Exception {
        internalTestWithSignatureAlgorithm("SHA256withECDSA", true);
    }

    /**
     * Test that setting a bogus SIGNATUREALGORITHM gives an error.
     *
     * @throws Exception 
     */
    @Test
    public void testWithBogusSignatureAlgorithm() throws Exception {
        internalTestWithSignatureAlgorithm("_unknown_", true);
    }

    /**
     * Test that setting a SIGNATUREALGORITHM with a capital With works.
     *
     * @throws Exception 
     */
    @Test
    public void testWithSignatureAlgorithmWithCapitalW() throws Exception {
        internalTestWithSignatureAlgorithm("SHA256WithRSA", false);
    }
    
    /**
     * Helper method testing with signature algorithm.
     * 
     * @throws Exception 
     */
    private void internalTestWithSignatureAlgorithm(final String sigAlg,
                                                    final boolean expectedError)
            throws Exception {
        final ZoneHashSigner instance = new ZoneHashSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };

        final WorkerConfig config = new WorkerConfig();

        config.setProperty("ACTIVE_KSKS", " key1 , key2");
        config.setProperty("ZSK_KEY_ALIAS_PREFIX", "example.com_Z_");
        config.setProperty("ZONE_NAME", "example.com.");
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("SIGNATUREALGORITHM", sigAlg);
        instance.init(WORKER, config, null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);
        
        if (expectedError) {
            assertTrue("contains error: " + fatalErrors.toString(),
                       fatalErrors.contains("Unsupported signature algorithm: " +
                                            sigAlg));
        } else {
            assertFalse("fatal errors doesn't mention unsupported signature algorithm: " + fatalErrors.toString(),
                        fatalErrors.toString().contains("Unsupported signature algorithm"));
        }
    }

//    /**
//     * Test that providing an incorrect value for DETACHEDSIGNATURE
//     * gives a fatal error.
//     * @throws Exception
//     */
//    @Test
//    public void testInit_incorrectDetachedSignatureValue() throws Exception {
//        LOG.info("testInit_incorrectDetachedSignatureValue");
//        WorkerConfig config = new WorkerConfig();
//        config.setProperty("DETACHEDSIGNATURE", "_incorrect-value--");
//        CMSSigner instance = createMockSigner(tokenRSA);
//        instance.init(1, config, new SignServerContext(), null);
//
//        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
//        assertTrue("conf errs: " + errors, errors.contains("DETACHEDSIGNATURE"));
//    }
    
    @Test
    public void testProtocol_default() throws Exception {
        protocolTest(null, DNSSEC.Algorithm.RSASHA256, "SHA-256");
    }
    
    @Test
    public void testProtocol_SHA256withRSA() throws Exception {
        protocolTest("SHA256withRSA", DNSSEC.Algorithm.RSASHA256, "SHA-256");
    }
    
    @Test
    public void testProtocol_SHA1withRSA() throws Exception {
        protocolTest("SHA1withRSA", DNSSEC.Algorithm.RSA_NSEC3_SHA1, "SHA-1");
    }
    
    @Test
    public void testProtocol_SHA512withRSA() throws Exception {
        protocolTest("SHA512withRSA", DNSSEC.Algorithm.RSASHA512, "SHA-512");
    }
    
    private void protocolTest(String signatureAlgorithmProperty, int expectedDnssecAlgorithm, String digestAlgorithm) throws Exception {
        LOG.info("testProtocol(" + signatureAlgorithmProperty + ")");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("ZSK_KEY_ALIAS_PREFIX", "example.net_Z_");
        config.setProperty("ACTIVE_KSKS", "example.net_K_1, example.net_K_2");
        config.setProperty("ZONE_NAME", "example.net.");
        if (signatureAlgorithmProperty != null) {
            config.setProperty("SIGNATUREALGORITHM", signatureAlgorithmProperty);
        }
        ZoneHashSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        LOG.info("Config errors: " + instance.getFatalErrors(null));

        // Pre-request
        final RequestMetadata preRequestMetadata = new RequestMetadata();
        preRequestMetadata.put("ZSK_SEQUENCE_NUMBER", "1");
        preRequestMetadata.put("SOA_TTL", "86400");
        final Properties preRequestBody = new Properties();
        
        // Pre-response
        final Properties preResponse = sendRequest(instance, preRequestMetadata, preRequestBody);
        final DNSKEYRecord dnskeyZ1 = (DNSKEYRecord) DNSKEYRecord.fromWire(Base64.decode(preResponse.getProperty("rr.dnskey.z1")), 37);
        final Date z1SigningTime = new Date(Long.parseLong(preResponse.getProperty("rr.dnskey.z1.signingtime")));
        final Date z1ExpireTime = new Date(Long.parseLong(preResponse.getProperty("rr.dnskey.z1.expiretime")));
        assertEquals("rr_dnskey_z1_algorithm from response", String.valueOf(expectedDnssecAlgorithm), preResponse.getProperty(ZoneHelper.RR_DNSKEY_Z1_ALGORITHM));
        assertEquals("dnskeyZ1 algorithm", expectedDnssecAlgorithm, dnskeyZ1.getAlgorithm());
        
        
        // Request
        final RequestMetadata requestMetadata = new RequestMetadata();
        requestMetadata.put("ZSK_SEQUENCE_NUMBER", "1");
        requestMetadata.put(ZoneHelper.RR_DNSKEY_Z1_ALGORITHM, preResponse.getProperty(ZoneHelper.RR_DNSKEY_Z1_ALGORITHM));
        requestMetadata.put(ZoneHelper.RR_DNSKEY_Z1_FOOTPRINT, preResponse.getProperty(ZoneHelper.RR_DNSKEY_Z1_FOOTPRINT));
        requestMetadata.put(ZoneHelper.RR_DNSKEY_Z1_SIGNINGTIME, preResponse.getProperty(ZoneHelper.RR_DNSKEY_Z1_SIGNINGTIME));
        requestMetadata.put(ZoneHelper.RR_DNSKEY_Z1_EXPIRETIME, preResponse.getProperty(ZoneHelper.RR_DNSKEY_Z1_EXPIRETIME));
        final Properties requestBody = new Properties();
        
        // Records to sign
        final Record record1 = new ARecord(new Name("foo1.example.com."), DClass.IN, 86400, InetAddress.getByName("192.168.1.1"));
        final RRset rrset1 = new RRset(record1);
        final RRSIGRecord sigRecord1 = ZoneHelper.createRrsigRecord(rrset1, dnskeyZ1, z1SigningTime, z1ExpireTime);
        final byte[] tbs1 = ZoneHelper.createToBeSignedData(sigRecord1, rrset1);
        final String signatureInput1 = ZoneHelper.toSignatureInput(tbs1, digestAlgorithm);
        requestBody.put("hash.1", signatureInput1);
        
        final Record record2 = new ARecord(new Name("foo2.example.com."), DClass.IN, 86400, InetAddress.getByName("192.168.1.2"));
        final RRset rrset2 = new RRset(record2);
        final RRSIGRecord sigRecord2 = ZoneHelper.createRrsigRecord(rrset2, dnskeyZ1, z1SigningTime, z1ExpireTime);
        final byte[] tbs2 = ZoneHelper.createToBeSignedData(sigRecord2, rrset2);
        final String signatureInput2 = ZoneHelper.toSignatureInput(tbs2, digestAlgorithm);
        requestBody.put("hash.2", signatureInput2);
        
        // Response
        final Properties response = sendRequest(instance, requestMetadata, requestBody);
        
        // Complete the signature record
        final RRSIGRecord finalSigRecord1 = ZoneHelper.createWithSignature(sigRecord1, Base64.decode(response.getProperty("sig.1")));
        LOG.info("Final signature record 1: " + finalSigRecord1.toString());
        final RRSIGRecord finalSigRecord2 = ZoneHelper.createWithSignature(sigRecord2, Base64.decode(response.getProperty("sig.2")));
        LOG.info("Final signature record 2: " + finalSigRecord2.toString());
        
        // Verify signature
        final DnsSecVerifier verifier = new DnsSecVerifier();
        
        final RRset sigSet1 = new RRset(rrset1);
        sigSet1.addRR(finalSigRecord1);
        SecurityStatus status = verifier.verify(sigSet1, dnskeyZ1);
        assertEquals(SecurityStatus.SECURE, status);
        
        final RRset sigSet2 = new RRset(rrset2);
        sigSet2.addRR(finalSigRecord2);
        status = verifier.verify(sigSet2, dnskeyZ1);
        assertEquals(SecurityStatus.SECURE, status);
    }

    private Properties sendRequest(final ZoneHashSigner instance, final RequestMetadata requestMetaData, final Properties requestBody) throws Exception {
        final RequestContext context = new RequestContext();
        context.put(RequestContext.TRANSACTION_ID, "0000-100-1");
        context.put(RequestContext.REQUEST_METADATA, requestMetaData);
        
        final StringBuilder sb = new StringBuilder();
        sb.append("sendRequest {\n");
        sb.append("\trequestMetaData:\n");
        
        requestMetaData.entrySet().forEach((entry) -> {
            sb.append("\t\t").append(entry.getKey()).append("=").append(entry.getValue()).append("\n");
        });
        
        sb.append("\trequest:\n");
        requestBody.entrySet().forEach((entry) -> {
            sb.append("\t\t").append(entry.getKey()).append("=").append(entry.getValue()).append("\n");
        });
        
        sb.append("}");
        
        LOG.info(sb.toString());
        

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(requestBody);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            SignatureRequest request = new SignatureRequest(100, requestData, responseData);
            SignatureResponse response = (SignatureResponse) instance.processData(request, context);

            final Properties responseProperties = new Properties();
            responseProperties.load(responseData.toReadableData().getAsInputStream());
            
            LOG.info("response: {\n" + responseProperties + "\n}");
            
            return responseProperties;
        }
    }
    
    /**
     * Create a mock signer instance for the tests.
     * This method can be overridden in test classes for extending signers that
     * want to inherit the tests from this class.
     * 
     * @param token Mock crypto token to use
     * @return Mock implementation
     */
    protected ZoneHashSigner createMockSigner(final MockedCryptoToken token) {
        return new MockedZoneHashSigner(token);
    }
}
