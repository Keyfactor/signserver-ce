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
package org.signserver.module.xades.validator;

import java.security.Security;
import java.util.Collections;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.signserver.common.GenericValidationRequest;
import org.signserver.common.GenericValidationResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.module.xades.signer.MockedCryptoToken;
import org.signserver.module.xades.signer.XAdESSignerUnitTest;
import org.signserver.server.WorkerContext;
import org.signserver.validationservice.common.Validation;

/**
 * Basic unit tests for the XAdESValidator class.
 *
 * Uses a hard coded XML document.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class XAdESValidator1UnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(XAdESSignerUnitTest.class);
    
    private static final String SIGNED_DOCUMENT1 = 
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"xmldsig-025b548b-c461-4fb4-a1fb-d95ec54b3cdf\">\n" +
            "<ds:SignedInfo>\n" +
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n" +
            "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n" +
            "<ds:Reference Id=\"xmldsig-025b548b-c461-4fb4-a1fb-d95ec54b3cdf-ref0\" Type=\"http://www.w3.org/2000/09/xmldsig#Object\" URI=\"#xmldsig-025b548b-c461-4fb4-a1fb-d95ec54b3cdf-object0\">\n" +
            "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n" +
            "<ds:DigestValue>xg51wjdF6iCIBbqklug05nGfjZ73tfmY+/WopRCFlRA=</ds:DigestValue>\n" +
            "</ds:Reference>\n" +
            "<ds:Reference Type=\"http://uri.etsi.org/01903#SignedProperties\" URI=\"#xmldsig-025b548b-c461-4fb4-a1fb-d95ec54b3cdf-signedprops\">\n" +
            "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n" +
            "<ds:DigestValue>EdX5QE5zNFRNDOtNO0C0NHaXU4jQqmt/I/d7LwYvarU=</ds:DigestValue>\n" +
            "</ds:Reference>\n" +
            "</ds:SignedInfo>\n" +
            "<ds:SignatureValue Id=\"xmldsig-025b548b-c461-4fb4-a1fb-d95ec54b3cdf-sigvalue\">\n" +
            "fL4dUIzJmE5Us6zwMx4m9h+lttg8LXybRbz6hCE0mkHMZtcHifFDqaxIwyJlaVkIUwbVPcm2mVbM\n" +
            "tzoOJbntlxcur8IAR8f/X29rHZ8oqWQoG9CHj/rmMQcgpDerV8d3mUg7LzPuBl1doJZpDV+olAFt\n" +
            "pUaVtZmAfT4cgGU2D9zktEv/11jNOP9jZpkivGO8qepVktUcrRENpIRFgwJ/o1RrYLSB0GyXpkB9\n" +
            "Hw+IGmM+OJhvdw8rWcA0Tw6zjstEUAwEJwhJ9KXexD4IQLvfI5ATra4FDoAZymcxmOXFLwKpDKkX\n" +
            "v5MbIVbCIpYgA0ECUtlBeYbN63Sr2iLULwBRsQ==\n" +
            "</ds:SignatureValue>\n" +
            "<ds:KeyInfo>\n" +
            "<ds:X509Data>\n" +
            "<ds:X509Certificate>\n" +
            "MIIE7DCCAtSgAwIBAgIITC/vp/LOZSMwDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJv\n" +
            "b3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYT\n" +
            "AlNFMB4XDTEzMDgxOTE0NTMyMVoXDTIzMDgyMDE0NTMyMVowSzEVMBMGA1UEAwwMWE1MIFNpZ25l\n" +
            "ciAxMRAwDgYDVQQLDAdUZXN0aW5nMRMwEQYDVQQKDApTaWduU2VydmVyMQswCQYDVQQGEwJTRTCC\n" +
            "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI8BZM1qIbtmUYdMjTghIQSFuBbxq2n/ZXUF\n" +
            "Wlr71YtJ/6jjzn/VyuADkulGBywlMa34nPivGEDnGqQcVa8eToHlWGojiQCiMIoDIvm1b38i64qK\n" +
            "YXSzwR3vxIrPD/WoQQkpBP9y1UG0uRlz/nCBosnipshfhZPLbd/tqJQprcAX1i03Ps4sYK4NpOrG\n" +
            "TMDyuyuz0Fl0MiHDhPiGGeDG1kru+Cj0DYs6IYNevzhOEcbAM+tSyrvKgMXi7vyS2meZMN5xeZ0V\n" +
            "Hu+Yu43YTgK/r9mV5L5jYfdYVVkUiLs3Lwq2TstDGnfrqoFgAei4Uf377221bHF61Ws9TMCmeEzO\n" +
            "cKsCAwEAAaOB0TCBzjBPBggrBgEFBQcBAQRDMEEwPwYIKwYBBQUHMAGGM2h0dHA6Ly92bW1hcmt1\n" +
            "c2NhMTo4MDgwL2VqYmNhL3B1YmxpY3dlYi9zdGF0dXMvb2NzcDAdBgNVHQ4EFgQUpkMNnroRqO/o\n" +
            "NKhuCXXhQke7HGUwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgF\n" +
            "ojAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3\n" +
            "DQEBCwUAA4ICAQAw2odWbIgWEZbO1BZQPXRZtQGBo+VlYcTEnBVn5MnM3VrSO35YySpdW7tr2y06\n" +
            "E7I6w7KZ9WxCkUHq3NH62kvgr2IKIaDninRS1Xu4TKQgEgrTUYlUGbmXsl6gsTngzhxPl3BnpMw8\n" +
            "VKm5fCP4rk06nUfL/lNxZmEJg4PhoOW9IeZlYsaZkvBk/ZsEO+kkXerLy5IVA+uaKGrm6mLb0FX0\n" +
            "nKm/Vat0gGHhkQwV208nphRhiVMXTGNi9epHOL27Y3pGUsgaWGslaI8SwC/HD9U2ttWVVDJ4xvW7\n" +
            "h5FhYSOvb6/NkByl90p4d3/3dFxbTbsyTb+5Y+vwaPIVlDDO6nEOF7h7CygVFe07HeqPJHjnaALZ\n" +
            "PGKg2ajMi8/PoVbGv2wa7lfxbzKolr5wT3kZTKiOShOt8FfK2WBksMwZ1NMdchtmug4tLjjKN6Ob\n" +
            "Thdhr+YnMVWq6Yr59YAz3+vP/+qtPIWXfU8FI2h/2J2JOp8GhPYDPNxSSm+BAlo9MRdYCQ2ypATN\n" +
            "yNjPKPlch3EA5efZgrli6/lW5i8aLSdZ5B7auKXNHXen2by9P7HTFTSGWqIC6Cl8DS9cH/5czgLP\n" +
            "EufzkLCabDmtsq6MoO3o7FJYXjwQHQKD4hfKDFWIr50GAoG4oT4KmqeFkLg/3SU6+7RQ8hcu82M4\n" +
            "Ckyc15pHnrPfKQ==\n" +
            "</ds:X509Certificate>\n" +
            "</ds:X509Data>\n" +
            "</ds:KeyInfo>\n" +
            "<ds:Object Id=\"xmldsig-025b548b-c461-4fb4-a1fb-d95ec54b3cdf-object0\"><root/></ds:Object>\n" +
            "<ds:Object><xades:QualifyingProperties xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" xmlns:xades141=\"http://uri.etsi.org/01903/v1.4.1#\" Target=\"#xmldsig-025b548b-c461-4fb4-a1fb-d95ec54b3cdf\"><xades:SignedProperties Id=\"xmldsig-025b548b-c461-4fb4-a1fb-d95ec54b3cdf-signedprops\"><xades:SignedSignatureProperties><xades:SigningTime>2013-08-21T15:22:23.083+02:00</xades:SigningTime><xades:SigningCertificate><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>VCymlxaOCJedLLqZxg6sZdrEyj2l5S8y0SppsJfcQCY=</ds:DigestValue></xades:CertDigest><xades:IssuerSerial><ds:X509IssuerName>C=SE,O=SignServer,OU=Testing,CN=DSS Root CA 10</ds:X509IssuerName><ds:X509SerialNumber>5489869975400113443</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert></xades:SigningCertificate></xades:SignedSignatureProperties><xades:SignedDataObjectProperties><xades:CommitmentTypeIndication><xades:CommitmentTypeId><xades:Identifier>http://uri.etsi.org/01903/v1.2.2#ProofOfApproval</xades:Identifier><xades:Description>Indicates that the signer has approved the content of the signed data object</xades:Description></xades:CommitmentTypeId><xades:AllSignedDataObjects/></xades:CommitmentTypeIndication></xades:SignedDataObjectProperties></xades:SignedProperties></xades:QualifyingProperties></ds:Object>\n" +
            "</ds:Signature>";

    private static final String ROOTCA_CERTIFICATE = 
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIFfzCCA2egAwIBAgIIMk1BOK8CwTwwDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzA4MTQyN1oXDTM2MDUyNzA4MTQyN1owTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgblgjTTkMp1QAhgWDprhvqE9zX1Ux/A/RTOu4G4f6CTkd6JEEkbdKZv+CKv4cRoVCtfO3wnOokFRw/1JMmHHiQ1Z//uDoDjo8jk8nek0ArFE9R5NT02wMJCQa/mP1wU9ZSl1tx3jQRUFB+rTNeCcPTft+1FL7UjYMdkRzl261IOlmXzDMA+EYIGJ2c2wYhOv2DqfQygNz5GOf0EFqlQZIt/pzopSS+0K8mNb53ROhg9GJujwzugSH5Z+r0fsVHbCV0QUkZBfkRo9KMcdaDEPa8xpYTjsFPqU6RcnGkVABhn8OS8SIWw2re1f+htj6p9EGbk1m0I9pWGBA9ktWnrqlqDXV+tEhhh1O4f+LHieoxiscrF7RXxlYqyam6oabfXsX3VAC0M1UkwIciE8wA1Sj/+dgoSMqvEDNDfwpEYt6l8Z8czDTWDi7MM2u5VY0nP3+A+PepKrOtrdaGSP396f4a7A3un1o6nQWHsyWQ7kc8GIn8zN5nykQaghGyYlHHYe1XUSPtHmxjbdsyztrkIis3cfjFne0XgPAiQuYx3T/B+po9BhGIUwCV0Qi/gWVN6NkydsbzMeRXELQYyK+lHgIGiEaBzQRRtXbnB+wQXi2IacJNdKqICwDsl/PvvcZI9ZV6pB/KIzB+8IJm0CLY24K0OXJs3Bqij8gmpvbI+o0wUCAwEAAaNjMGEwHQYDVR0OBBYEFCB6Id7orbsCqPtxWKQJYrnYWAWiMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUIHoh3uituwKo+3FYpAliudhYBaIwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQAxFvpOZF6Kol48cQeKWQ48VAe+h5dmyKMfDLDZX51IRzfKKsHLpFPxzGNw4t9Uv4YOR0CD9z81dR+c93t1lwwIpKbx9Qmq8jViHEHKYD9FXThM+cVpsT25pg35m3ONeUX/b++l2d+2QNNTWMvdsCtaQdybZqbYFIk0IjPwLLqdsA8Io60kuES4JnQahPdLkfm70rgAdmRDozOfSDaaWHY20DovkfvKUYjPR6MGAPD5w9dEb4wp/ZjATblyZnH+LTflwfftUAonmAw46E0Zgg143sO6RfOOnbwjXEc+KXd/KQ6kTQ560mlyRd6q7EIDYRfD4n4agKV2R5gvVPhMD0+IK7kagqKNfWa9z8Ue2N3MedyWnb9wv4wC69qFndGaIfYADkUykoOyLsVVteJ70PVJPXO7s66LucfD2R0wo2MpuOYCsTOm7HHS+uZ9VjHl2qQ0ZQG89Xn+AXnzPbk1INe2z0lq3hzCW5DTYBKsJEexErzMpLwiEqUYJUfR9EeCM8UPMtLSqz1utdPoIYhULGzt5lSJEpMHMbquYfWJxQiKCbvfxQsP5dLUMEIqTgjNdo98OlM7Z7zjYH9Kimz3wgAKSAIoQZr7Oy1dMHO5GK4jBtZ8wgsyyQ6DzQQ7R68XFVKarIW8SATeyubAP+WjdMwk/ZXzsDjMZEtENaBXzAefYA==\n" +
            "-----END CERTIFICATE-----";
    
    private static MockedCryptoToken token;
    

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test of init method, of class XAdESValidator.
     */
    @Test
    public void testInit_ok() {
        LOG.info("init");
        int signerId = 4711;
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", ROOTCA_CERTIFICATE);
        
        WorkerContext workerContext = null;
        EntityManager em = null;
        XAdESValidator instance = new XAdESValidator();
        instance.init(signerId, config, workerContext, em);
        
        assertEquals(Collections.EMPTY_LIST, instance.getFatalErrors());
    }
    
    /**
     * Test of init method with missing TRUSTANCHORS, of class XAdESValidator.
     */
    @Test
    public void testInit_missingTRUSTANCHORS() throws Exception {
        LOG.info("init");
        int signerId = 4711;
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CERTIFICATES", ROOTCA_CERTIFICATE);
        
        WorkerContext workerContext = null;
        EntityManager em = null;
        XAdESValidator instance = new XAdESValidator();
        instance.init(signerId, config, workerContext, em);
        
        String errors = instance.getFatalErrors().toString();
        assertTrue("error: " + errors, errors.contains("TRUSTANCHORS"));
        
        // Sending an request should give error
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-200-0");
        GenericValidationRequest request = new GenericValidationRequest(200, SIGNED_DOCUMENT1.getBytes("UTF-8"));
        try {
            instance.processData(request, requestContext);
            fail("Should have thrown SignServer exception");
        } catch (IllegalRequestException ex) {
            fail("Should have thrown SignServerException but was: " + ex);
        }
        catch (SignServerException expected) {} // NOPMD
    }

    /**
     * Test of processData method, of class XAdESValidator.
     */
    @Test
    public void testProcessData_basicValidation() throws Exception {
        LOG.info("processData");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", ROOTCA_CERTIFICATE);
        config.setProperty("REVOCATION_CHECKING", "false");
        
        instance.init(4711, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-201-0");
        GenericValidationRequest request = new GenericValidationRequest(201, SIGNED_DOCUMENT1.getBytes("UTF-8"));
        GenericValidationResponse response = (GenericValidationResponse) instance.processData(request, requestContext);
        
        assertTrue("valid document", response.isValid());
        assertNotNull("returned signer cert", response.getSignerCertificate());
        assertEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidation().getStatus());
    }
    
}