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
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;

import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.util.encoders.Base64;
import org.ejbca.util.CertTools;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;

import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.WorkerSessionMock;

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

    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(MSAuthCodeTimeStampSignerTest.class);
    private static final String SIGN_CERT = "MIIElTCCAn2gAwIBAgIITz1ZKtegWpgwDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UE"
            + "AwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNp"
            + "Z25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzA5NTE0NVoXDTIxMDUyNzA5"
            + "NTE0NVowRzERMA8GA1UEAwwIU2lnbmVyIDQxEDAOBgNVBAsMB1Rlc3RpbmcxEzAR"
            + "BgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEF"
            + "AAOCAQ8AMIIBCgKCAQEAnCGlYABPTW3Jx607cdkHPDJEGXpKCXkI29zj8BxCIvC3"
            + "3kyGZB6M7EICU+7vt200u1TmSjx2auTfZI6sA2cDsESlMhKJ+8nj2uj1f5g9MYRb"
            + "+IIq1IIhDArWwICswnZkWL/5Ncggg2bNcidCblDy5SUQ+xMeXtJQWCU8Zn3a+ySZ"
            + "Z1ZiYZ10gUu5JValsuOb8YpcT/pqBPF0cgEy6mIe3ANolzxLKNUBYAsQzQnCvgx+"
            + "GqgbzYHo8fkppSGUFVYdFI0MC9CBT72eOxxQoguICWXus8BdIwebZDGQdluKvTNs"
            + "ig4hM39G6WvPqoEi9I86VhY9mSyY+WOeU5Y3ZsC8CQIDAQABo38wfTAdBgNVHQ4E"
            + "FgQUGqddBv2s8iEa5B98MVTbQ2HiFkAwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAW"
            + "gBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYw"
            + "FAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4ICAQB8HpFOfiTb"
            + "ylu06tg0yqvix93zZrJWSKT5PjwpqAU+btQ4fFy4GUBG6VuuVr27+FaFND3oaIQW"
            + "BXdQ1+6ea3Nu9WCnKkLLjg7OjBNWw1LCrHXiAHdIYM3mqayPcf7ezbr6AMnmwDs6"
            + "/8YAXjyRLmhGb23M8db+3pgTf0Co/CoeQWVa1eJObH7aO4/Koeg4twwbKG0MjwEY"
            + "ZPi0ZWB93w/llEHbvMNI9dsQWSqIU7W56KRFN66WdqFhjdVPyg86NudH+9jmp4x1"
            + "Ac9GKGNOYYfDnQCdsrJwZMvcI7bZykbd77ZC3zBzuaISAeRJq3rjHygSeKPHCYDW"
            + "zAVEP9yaO0fL7HMZ2uqHxokvuOo5SxgVfvLr+kT4ioQHz+r9ehkCf0dbydm7EqyJ"
            + "Y7YSFUDEqk57dnZDxy7ZgUA/TZf3I3rPjSopDxqiqJbm9L0GPW3zk0pAZx7dgLcq"
            + "2I8fv+DBEKqJ47/H2V5aopxsRhiKC5u8nEEbAMbBYgjGQT/5K4mBt0gUJFNek7vS"
            + "a50VH05u8P6yo/3ppDxGCXE2d2JfWlEIx7DRWWij2PuOgDGkvVt2soxtp8Lx+kS6"
            + "K+G+tA5BGZMyEPdqAakyup7udi4LoB0wfJ58Jr5QNHCx4icUWvCBUM5CTcH4O/pQ"
            + "oj/7HSYZlqigM72nR8f/gv1TwLVKz+ygzg==";
    
    private static final String SIGNED_DATA_OID = "1.2.840.113549.1.7.2";
    private static final String CONTENT_TYPE_OID = "1.2.840.113549.1.9.3";
    private static final String SIGNING_TIME_OID = "1.2.840.113549.1.9.5";
    private static final String MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4";
    private static final String SIGNING_CERT_OID = "1.2.840.113549.1.9.16.2.12";
    private static final String SHA1_OID = "1.3.14.3.2.26";
    private static final String SHA256_OID = "2.16.840.1.101.3.4.2.1";
    private static final String CN_OID = "2.5.4.3";
    private static final String OU_OID = "2.5.4.11";
    private static final String O_OID = "2.5.4.10";
    private static final String C_OID = "2.5.4.6";
    
    private static final String CN = "DSS Root CA 10";
    private static final String OU = "Testing";
    private static final String O = "SignServer";
    private static final String C = "SE";
  
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
            final byte[] requestData, final boolean includeSigningCertAttr) throws Exception {
        SignServerUtil.installBCProvider();
        
        final String CRYPTOTOKEN_CLASSNAME =
                "org.signserver.server.cryptotokens.HardCodedCryptoToken";
        
        ProcessRequest signRequest = null;
        
        final GlobalConfigurationSessionMock globalConfig
                = new GlobalConfigurationSessionMock();
        final WorkerSessionMock workerMock = new WorkerSessionMock(globalConfig);
        
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("NAME", "TestMSAuthCodeTimeStampSigner");
        config.setProperty("AUTHTYPE", "NOAUTH");
        config.setProperty("TIMESOURCE", "org.signserver.server.ZeroTimeSource");
        config.setProperty("SIGNATUREALGORITHM", signingAlgo);
        
        if (includeSigningCertAttr) {
            config.setProperty("INCLUDE_SIGNING_CERTIFICATE_ATTRIBUTE", "true");
        }
        
        workerMock.setupWorker(SIGNER_ID, CRYPTOTOKEN_CLASSNAME, config,
                    new MSAuthCodeTimeStampSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
        workerMock.reloadConfiguration(SIGNER_ID);
        
        // create sample hard-coded request
        signRequest = new GenericSignRequest(REQUEST_ID, requestData);
        
        GenericSignResponse resp = (GenericSignResponse) workerMock.process(SIGNER_ID, signRequest, new RequestContext());
        
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
        
        // if INCLUDE_SIGNING_CERTIFICATE_ATTRIBUTE is set to false, the attribute should not be included
        if (!includeSigningCertAttr) {
            assertEquals("Number of attributes", 3, asn1seq3.size());
        } else {
            final ASN1Sequence scAttr = ASN1Sequence.getInstance(asn1seq3.getObjectAt(3));
            final ASN1ObjectIdentifier scOid = ASN1ObjectIdentifier.getInstance(scAttr.getObjectAt(0));
            
            assertEquals("Invalid OID for content", SIGNING_CERT_OID, scOid.getId());
            
            // calculate expected hash
            final Certificate cert = CertTools.getCertfromByteArray(Base64.decode(SIGN_CERT.getBytes()));
            final byte[] digest = MessageDigest.getInstance("SHA-1").digest(cert.getEncoded());
            
            // find hash in returned structure
            final ASN1Set set = ASN1Set.getInstance(scAttr.getObjectAt(1));
            final ASN1Sequence s1 = ASN1Sequence.getInstance(set.getObjectAt(0));
            final ASN1Sequence s2 = ASN1Sequence.getInstance(s1.getObjectAt(0));
            final ASN1Sequence s3 = ASN1Sequence.getInstance(s2.getObjectAt(0));
            final ASN1OctetString hashOctetString = ASN1OctetString.getInstance(s3.getObjectAt(0)); 
            
            assertTrue("Hash doesn't match", Arrays.equals(digest, hashOctetString.getOctets()));

            // expected serial number
            final BigInteger sn = ((X509Certificate) cert).getSerialNumber();

            // find serial number in structure
            final ASN1Sequence s4 = ASN1Sequence.getInstance(s3.getObjectAt(1));
            final ASN1Integer snValue = ASN1Integer.getInstance(s4.getObjectAt(1));
            
            assertEquals("Serial number doesn't match", sn, snValue.getValue());
            
            // examine issuer
            final ASN1Sequence s5 = ASN1Sequence.getInstance(s4.getObjectAt(0));
            final ASN1TaggedObject obj = ASN1TaggedObject.getInstance(s5.getObjectAt(0));
            final ASN1Sequence s6 = ASN1Sequence.getInstance(obj.getObject());
            
            // expect 4 DN components in the signing cert
            assertEquals("Number of DN components", 4, s6.size());
            
            final Enumeration objects = s6.getObjects();
            while (objects.hasMoreElements()) {
                final ASN1Set component = ASN1Set.getInstance(objects.nextElement());
                final ASN1Sequence seq = ASN1Sequence.getInstance(component.getObjectAt(0));
                final ASN1ObjectIdentifier dnOid = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
                
                if (CN_OID.equals(dnOid.getId())) {
                    final DERUTF8String cn = DERUTF8String.getInstance(seq.getObjectAt(1));
                    assertEquals("Issuer CN doesn't match", CN, cn.getString());
                } else if (OU_OID.equals(dnOid.getId())) {
                    final DERUTF8String ou = DERUTF8String.getInstance(seq.getObjectAt(1));
                    assertEquals("Issuer OU doesn't match", OU, ou.getString());
                } else if (O_OID.equals(dnOid.getId())) {
                    final DERUTF8String o = DERUTF8String.getInstance(seq.getObjectAt(1));
                    assertEquals("Issuer O doesn't match", O, o.getString());
                } else if (C_OID.equals(dnOid.getId())) {
                    final DERPrintableString c = DERPrintableString.getInstance(seq.getObjectAt(1));
                    assertEquals("Issuer C doesn't match", C, c.getString());
                } else {
                    fail("Unexpected issuer DN component");
                }
            }
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
    }
    
    /**
     * Test of processData method, of class MSAuthCodeTimeStampSigner.
     */
    public void testProcessDataSHA1withRSA() throws Exception {
    	testProcessDataWithAlgo("SHA1withRSA", SHA1_OID, REQUEST_DATA.getBytes(), false);
    }
    
    public void testProcessDataSHA256withRSA() throws Exception {
    	testProcessDataWithAlgo("SHA256withRSA", SHA256_OID, REQUEST_DATA.getBytes(), false);
    }
    
    /**
     * Test with requestData with zero length. Shall give an IllegalRequestException.
     * @throws Exception
     */
    public void testEmptyRequest() throws Exception {
        try {
            testProcessDataWithAlgo("SHA1withRSA", SHA1_OID, new byte[0], false);
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
            testProcessDataWithAlgo("SHA1withRSA", SHA1_OID, "bogus request".getBytes(), false);
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
            testProcessDataWithAlgo("SHA1withRSA", SHA1_OID, null, false);
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
        testProcessDataWithAlgo("SHA1withRSA", SHA1_OID, REQUEST_DATA.getBytes(), true);
    }
}
