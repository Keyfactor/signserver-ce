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

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Collections;
import jakarta.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;
import org.signserver.module.xades.signer.XAdESSignerUnitTest;
import org.signserver.server.WorkerContext;
import org.signserver.common.data.DocumentValidationRequest;
import org.signserver.common.data.DocumentValidationResponse;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.testutils.ModulesTestCase;
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
    
    private static final String SIGNED_DOCUMENT1
            = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"xmldsig-e106dc41-1ce1-42e1-8498-840b82449ea1\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><ds:Reference Id=\"xmldsig-e106dc41-1ce1-42e1-8498-840b82449ea1-ref0\" Type=\"http://www.w3.org/2000/09/xmldsig#Object\" URI=\"#xmldsig-e106dc41-1ce1-42e1-8498-840b82449ea1-object0\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>7yTzK+OxhxetHwos5DO3GQEcQ7rxBVPOwGFM6iAIG68=</ds:DigestValue></ds:Reference><ds:Reference Type=\"http://uri.etsi.org/01903#SignedProperties\" URI=\"#xmldsig-e106dc41-1ce1-42e1-8498-840b82449ea1-signedprops\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>POOUO7EPOgQJFzNwvJ0e86duQ9flyPi0UZj4J1A9Zz0=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue Id=\"xmldsig-e106dc41-1ce1-42e1-8498-840b82449ea1-sigvalue\">hanSj66DDnKU7O/DEkd/4MvicENQZmn4bDEGdM0wPVIZQf8XznLgFeatcUhXM4jc7pvKF90I/OufJ0I35y69yHerCJXxB4pLQCXQ58PZA7lbfaGOmEGLydEiCQWQyFkFTSZp964k9s3cMSwvt4/BLF+s+YCTW3m9+kks6XOjx5/iEM1wngcJEF5uohiAw6XIMqge5WOOQLFGZOefvQn7lyTmyef0RbnLiv25xfXxSTGdiiCNGTAC+w/azhqIh/ILF0QqJE49Bf+lLxxHrUpMcpZt5mgyCoB0B9BkbQyHz2agSZs16K1q+ruLjiwbaVHEw3iRBdlh6j2iE6tcC6HKvw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEmDCCAoCgAwIBAgIIa4ipW9G59Z0wDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTE2MDMwMzA4MjQwOVoXDTM2MDIyNzA4MjQwOVowSjEUMBIGA1UEAwwLc2lnbmVyMDAwMDExEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApzvRZ6gX/u2T1AqL7EVrpKHEFDtKlBehjqJ05/kIzFNbGNkmTLQkbCRRirfHcd6jhY9wmFnYFTTHBS9JFWI7Q6Q/nehHApSaoh+eb5QrZYW2Cq5wLrQg18ckpecarXratsPQEKvTGWBCnJ1bhHmMeWHj56LYIB2EqES09gmKIVbNoAX/XymZ3lDgtfGXUc5SndTh1iIPFVMUzRbXoSvZGIfvQ6rRJDVS3/epBRfWtGzLaDK+dXMHisLsOahQARp5XU8DXd5+CwZC1dA+zQNixYEhStHXVuKfv4a89ONSpEdv2KHgOLiQP2N+hjszzSasRbhwLSENMEbeL5GbMIJTRQIDAQABo38wfTAdBgNVHQ4EFgQUlkvLMTR+fW1eSjV4irWUdoJifMwwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4ICAQANg0pIIifUnDHjffnpiep7eITU6V6odovsj3+1tYIaAahW+HtI5T2ishEt++huFiUFIdwbFyF4Ep5cQe9cMfQghUJ//YqC1WHnxVQH234ELdO1FzaC1YcHis2zeW7HFpugd9WrLgms/p2gXTLkLEfbUVE5ujUjelBUKyIA3ADDnWRxaz2vlOvRV+8ZgrvxSN+jYkrASeoDHeBh9qGknu1AmgaIUuQV6j/SSuf9+em3E7RSpFzOFwQTKq1MlKcxb3EC32O/JHu8T8jHWHZDmq2IkmwyGm3vTJH9bLNKvgM+wLWBJpbU5Ku/ijRNvOCAVrt90QKlMtA2/JZfLqZFiBNdB43VrM6cxWMdCL7gRIb50rR/CNAgblHq0DvpnXwS16SdaEibH6LjzTIJjoLwVbW+23j5w5r+XgxeNpoGxD5WY+Kq/h7D4eoL3e+oXHEfNwvXEuuRFpFXv4+4kOibRklG79VHSXEWclMvMlplIqHjHYh4gGSyvktCkV7YmqWteK9NEKeLOFoJ5Y5S4S9a+aCFkaHoUrW/PwR8Qp/0vOCK8+UduaDVbEQaM8Z2KeZwWafVdFxgb41nu6vcDVL/OQU0JyvdmNYmVoujboC3kNVfYJRgWeGceW2yo5anh5EuVwpMDncNHRF8V0TNwfORKDMmKoX5rcdgjmrR7Ebh29qalg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo><ds:Object Id=\"xmldsig-e106dc41-1ce1-42e1-8498-840b82449ea1-object0\"><root/></ds:Object><ds:Object><xades:QualifyingProperties xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" xmlns:xades141=\"http://uri.etsi.org/01903/v1.4.1#\" Target=\"#xmldsig-e106dc41-1ce1-42e1-8498-840b82449ea1\"><xades:SignedProperties Id=\"xmldsig-e106dc41-1ce1-42e1-8498-840b82449ea1-signedprops\"><xades:SignedSignatureProperties><xades:SigningTime>2023-08-28T13:22:18.702+02:00</xades:SigningTime><xades:SigningCertificate><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>8qawQMVRT87mKlonLZjgfwlbrOiDr5iO2B1f5NO4ZvE=</ds:DigestValue></xades:CertDigest><xades:IssuerSerial><ds:X509IssuerName>c=SE,o=SignServer,ou=Testing,cn=DSS Root CA 10</ds:X509IssuerName><ds:X509SerialNumber>7748629370716681629</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert></xades:SigningCertificate></xades:SignedSignatureProperties></xades:SignedProperties></xades:QualifyingProperties></ds:Object></ds:Signature>";

    private static final String ROOTCA_CERTIFICATE = 
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIFfzCCA2egAwIBAgIIMk1BOK8CwTwwDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzA4MTQyN1oXDTM2MDUyNzA4MTQyN1owTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgblgjTTkMp1QAhgWDprhvqE9zX1Ux/A/RTOu4G4f6CTkd6JEEkbdKZv+CKv4cRoVCtfO3wnOokFRw/1JMmHHiQ1Z//uDoDjo8jk8nek0ArFE9R5NT02wMJCQa/mP1wU9ZSl1tx3jQRUFB+rTNeCcPTft+1FL7UjYMdkRzl261IOlmXzDMA+EYIGJ2c2wYhOv2DqfQygNz5GOf0EFqlQZIt/pzopSS+0K8mNb53ROhg9GJujwzugSH5Z+r0fsVHbCV0QUkZBfkRo9KMcdaDEPa8xpYTjsFPqU6RcnGkVABhn8OS8SIWw2re1f+htj6p9EGbk1m0I9pWGBA9ktWnrqlqDXV+tEhhh1O4f+LHieoxiscrF7RXxlYqyam6oabfXsX3VAC0M1UkwIciE8wA1Sj/+dgoSMqvEDNDfwpEYt6l8Z8czDTWDi7MM2u5VY0nP3+A+PepKrOtrdaGSP396f4a7A3un1o6nQWHsyWQ7kc8GIn8zN5nykQaghGyYlHHYe1XUSPtHmxjbdsyztrkIis3cfjFne0XgPAiQuYx3T/B+po9BhGIUwCV0Qi/gWVN6NkydsbzMeRXELQYyK+lHgIGiEaBzQRRtXbnB+wQXi2IacJNdKqICwDsl/PvvcZI9ZV6pB/KIzB+8IJm0CLY24K0OXJs3Bqij8gmpvbI+o0wUCAwEAAaNjMGEwHQYDVR0OBBYEFCB6Id7orbsCqPtxWKQJYrnYWAWiMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUIHoh3uituwKo+3FYpAliudhYBaIwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQAxFvpOZF6Kol48cQeKWQ48VAe+h5dmyKMfDLDZX51IRzfKKsHLpFPxzGNw4t9Uv4YOR0CD9z81dR+c93t1lwwIpKbx9Qmq8jViHEHKYD9FXThM+cVpsT25pg35m3ONeUX/b++l2d+2QNNTWMvdsCtaQdybZqbYFIk0IjPwLLqdsA8Io60kuES4JnQahPdLkfm70rgAdmRDozOfSDaaWHY20DovkfvKUYjPR6MGAPD5w9dEb4wp/ZjATblyZnH+LTflwfftUAonmAw46E0Zgg143sO6RfOOnbwjXEc+KXd/KQ6kTQ560mlyRd6q7EIDYRfD4n4agKV2R5gvVPhMD0+IK7kagqKNfWa9z8Ue2N3MedyWnb9wv4wC69qFndGaIfYADkUykoOyLsVVteJ70PVJPXO7s66LucfD2R0wo2MpuOYCsTOm7HHS+uZ9VjHl2qQ0ZQG89Xn+AXnzPbk1INe2z0lq3hzCW5DTYBKsJEexErzMpLwiEqUYJUfR9EeCM8UPMtLSqz1utdPoIYhULGzt5lSJEpMHMbquYfWJxQiKCbvfxQsP5dLUMEIqTgjNdo98OlM7Z7zjYH9Kimz3wgAKSAIoQZr7Oy1dMHO5GK4jBtZ8wgsyyQ6DzQQ7R68XFVKarIW8SATeyubAP+WjdMwk/ZXzsDjMZEtENaBXzAefYA==\n" +
            "-----END CERTIFICATE-----";


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
        config.setProperty(WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        config.setProperty("TRUSTANCHORS", ROOTCA_CERTIFICATE);
        
        WorkerContext workerContext = null;
        EntityManager em = null;
        XAdESValidator instance = new XAdESValidator();
        instance.init(signerId, config, workerContext, em);
        
        assertEquals(Collections.EMPTY_LIST, instance.getFatalErrors(null));
    }
    
    /**
     * Test of init method with missing TRUSTANCHORS, of class XAdESValidator.
     * 
     * @throws java.lang.Exception
     */
    @Test(expected = SignServerException.class)
    public void testInit_missingTRUSTANCHORS() throws Exception {
        LOG.info("init");
        int signerId = 4711;
        WorkerConfig config = new WorkerConfig();
        config.setProperty(WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        config.setProperty("CERTIFICATES", ROOTCA_CERTIFICATE);
        
        WorkerContext workerContext = null;
        EntityManager em = null;
        XAdESValidator instance = new XAdESValidator();
        instance.init(signerId, config, workerContext, em);
        
        String errors = instance.getFatalErrors(null).toString();
        assertTrue("error: " + errors, errors.contains("TRUSTANCHORS"));
        
        // Sending an request should give error
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-200-0");
        
        try (CloseableReadableData requestData = ModulesTestCase.createRequestData(SIGNED_DOCUMENT1.getBytes(StandardCharsets.UTF_8))) {
            DocumentValidationRequest request = new DocumentValidationRequest(200, requestData);
            instance.processData(request, requestContext);
            fail("Should have thrown SignServer exception");
        } catch (IllegalRequestException ex) {
            fail("Should have thrown SignServerException but was: " + ex);
        }
    }

    /**
     * Test of processData method, of class XAdESValidator.
     * 
     * @throws java.lang.Exception
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
        try (CloseableReadableData requestData = ModulesTestCase.createRequestData(SIGNED_DOCUMENT1.getBytes(StandardCharsets.UTF_8))) {
            DocumentValidationRequest request = new DocumentValidationRequest(201, requestData);
            DocumentValidationResponse response = (DocumentValidationResponse) instance.processData(request, requestContext);

            assertTrue("valid document", response.isValid());
            assertNotNull("returned signer cert", response.getCertificateValidationResponse().getValidation().getCertificate());
            assertEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
        }
    }
    
}