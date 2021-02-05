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
package org.signserver.test.validationws.v31;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Map;
import java.util.Properties;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy;
import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.validationservice.common.ValidationServiceConstants;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * Test calling ValidationWSService using SignServer 3.1 WSDL.
 *
 * This tests assumes that test-configuration.properties as been applied to
 * SignServer.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ValidationWSServiceTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(ValidationWSServiceTest.class);

    /** Endpoint URL. */
    private final String ENDPOINT =
            "https://" + getHTTPHost() + ":" + getPublicHTTPSPort() + "/signserver/validationws/validationws?wsdl";

    private static final String[] CONF_FILES = {
        "signserver_deploy.properties",
        "conf/signserver_deploy.properties",
    };

    private static final String WORKER_NAME
            = "ValidationWSServiceTest_CertValidationWorker1";

    private static final String NONEXISTING_WORKER = "_NonExistingWorker123_";

    /**
     * Certificate for xmlsigner4.
     * <pre>
     * Serial Number: 73:9a:2f:10:6e:81:ba:04:77:2d:03:1a:66:02:a0:a5:49:78:b1:60
     *  Signature Algorithm: dsaWithSHA1
     *  Issuer: CN=DemoRootCA2, OU=EJBCA, O=SignServer Sample, C=SE
     *  Validity
     *      Not Before: Mon Dec 30 14:41:15 CET 2019
     *      Not After : Fri Nov 10 17:09:48 CET 2034
     *  Subject: CN=xmlsigner4
     * </pre>
     */
    static final String CERT_XMLSIGNER4 =
        "MIIDLDCCAuugAwIBAgIUc5ovEG6BugR3LQMaZgKgpUl4sWAwCQYHKoZIzjgEAzBPMRQwEgYDVQQDDAtEZW1vUm9vdENBMjEOMAwGA1UECwwFRUpCQ0ExGjAYBgNVBAoMEVNpZ25TZXJ2ZXIgU2FtcGxlMQswCQYDVQQGEwJTRTAeFw0xOTEyMzAxMzQxMTVaFw0zNDExMTAxNjA5NDhaMBUxEzARBgNVBAMMCnhtbHNpZ25lcjQwggG4MIIBLAYHKoZIzjgEATCCAR8CgYEA/X9TgR11EilS30qcLuzk5/YRt1I870QAwx4/gLZRJmlFXUAiUftZPY1Y+r/F9bow9subVWzXgTuAHTRv8mZgt2uZUKWkn5/oBHsQIsJPu6nX/rfGG/g7V+fGqKYVDwT7g/bTxR7DAjVUE1oWkTL2dfOuK2HXKu/yIgMZndFIAccCFQCXYFCPFSMLzLKSuYKi64QL8Fgc9QKBgQD34aCF1ps93su8q1w2uFe5eZSvu/o66oL5V0wLPQeCZ1FZV4661FlP5nEHEIGAtEkWcSPoTCgWE7fPCTKMyKbhPBZ6i1R8jSjgo64eK7OmdZFuo38L+iE1YvH7YnoBJDvMpPG+qFGQiaiD3+Fa5Z8GkotmXoB7VSVkAUw7/s9JKgOBhQACgYEA1CXfT00olSOapmZl4zT1/tUQzOzttQ/DCB8qYwH5fKD4cw1O2IutdntOP+Pd+Q6PV6r/cckmpvO12/sMpxWOmY1oio44L8Pl76MWqKiBecAsNgxjXkXiFdJ8llhTj9Z8vSYP8TUyY4UaITm3oZOp60eamFL93LjvpOkrDj7orXijfzB9MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUSd8VLspema6A95RZt58PwIQj3iUwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMB0GA1UdDgQWBBRqEubbKMwapnZFeqgUNRFEkKGpWjAOBgNVHQ8BAf8EBAMCBeAwCQYHKoZIzjgEAwMwADAtAhQ9OV4HFv9pTpRM4okw/R+H+jtgBgIVAIJfnJ5H8FRcjOANlGL61tg5ciJC";


    private ValidationWS ws;
    private final SSLSocketFactory socketFactory;

    public ValidationWSServiceTest() {
        super();
        socketFactory = setupKeystores();
    }

    /** Setup keystores for SSL. **/
    protected SSLSocketFactory setupKeystores() {
        Properties config = new Properties();

        final File home;
        final File path1 = new File("../..");
        final File path2 = new File(".");
        if (new File(path1, "res/deploytools/app.properties").exists()) {
            home = path1;
        } else if (new File(path2, "res/deploytools/app.properties").exists()) {
            home = path2;
        } else {
            throw new RuntimeException("Unable to detect SignServer path");
        }

        File confFile = null;
        for (String file : CONF_FILES) {
            final File f = new File(home, file);
            if (f.exists()) {
                confFile = f;
                break;
            }
        }
        if (confFile == null) {
            throw new RuntimeException("No signserver_deploy.properties found");
        } else {

            try {
                config.load(new FileInputStream(confFile));
            } catch (FileNotFoundException ignored) {
                LOG.debug("No signserver_deploy.properties");
            } catch (IOException ex) {
                LOG.error("Not using signserver_deploy.properties: " + ex.getMessage());
            }

            final File truststoreFile = new File(home, "p12/truststore.jks");
            final String truststorePassword =
                    config.getProperty("java.truststorepassword", "changeit");

            SSLSocketFactory socketFactory = null;

            try {
                KeyStore keystore = KeyStore.getInstance("JKS");
                keystore.load(new FileInputStream(truststoreFile),
                              truststorePassword.toCharArray());

                final TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
                tmf.init(keystore);

                final SSLContext context = SSLContext.getInstance("TLS");
                context.init(null, tmf.getTrustManagers(), new SecureRandom());

                socketFactory = context.getSocketFactory();
            } catch (KeyStoreException | IOException |
                     NoSuchAlgorithmException | CertificateException |
                     KeyManagementException e) {
                LOG.error("Failed to load truststore: " + e.getMessage());
            }

            return socketFactory;
        }
    }

    @Before
    public void setUp() {
        LOG.info("Initilizing test using WS URL: " + getWsEndPointUrl());
        final URL resource =
                getClass().getResource("/org/signserver/test/validationws/ValidationWS.wsdl");
        final QName qname
                = new QName("gen.ws.validationservice.protocol.signserver.org",
                "ValidationWSService");
        final ValidationWSService wsService =
                new ValidationWSService(resource, qname);
        ws =  wsService.getValidationWSPort();

        final BindingProvider bp = (BindingProvider) ws;
        final Map<String, Object> requestContext = bp.getRequestContext();

        requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
                           getWsEndPointUrl());

        if (socketFactory != null) {
            final Client client = ClientProxy.getClient(bp);
            final HTTPConduit http = (HTTPConduit) client.getConduit();
            final TLSClientParameters params = new TLSClientParameters();

            params.setSSLSocketFactory(socketFactory);
            http.setTlsClientParameters(params);

            final HTTPClientPolicy policy = http.getClient();
            policy.setAutoRedirect(true);
        }
    }

    /**
     * Overridden by org.signserver.test.validationws.v32.ValidationWSServiceTest.
     *
     * @return WS endpoint URL
     */
    protected String getWsEndPointUrl() {
    	return ENDPOINT;
    }

    WorkerSession workerSession = getWorkerSession();

    @Test
    public void test00SetupDatabase() throws Exception {
        addSigner("org.signserver.validationservice.server.ValidationServiceWorker", 7101, "ValidationWSServiceTest_CertValidationWorker1", true);
        workerSession.setWorkerProperty(7101, "VAL1.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");
        workerSession.setWorkerProperty(7101, "VAL1.TESTPROP", "TEST");
        workerSession.setWorkerProperty(7101, "VAL1.REVOKED", "");

        // Issuer 1: CN=AdminCA1, O=EJBCA Sample, C=SE
        workerSession.setWorkerProperty(7101, "VAL1.ISSUER1.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\nMIIDUzCCAjugAwIBAgIIKvuaicGKsjUwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UEAwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0UwHhcNMDgxMTI0MTIwMDUwWhcNMTgxMTIyMTIwMDUwWjA3MREwDwYDVQQDDAhBZG1pbkNBMTEVMBMGA1UECgwMRUpCQ0EgU2FtcGxlMQswCQYDVQQGEwJTRTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIG+Lo4CGuFXfsJF0Py5k9zAWaPUtqBpBBZ+O7V8Mj0JoJgPxzkneohDp2B66+/sbw3/MTDJhmhBNG0kGViT1gzEAMiZ7KS1UqT1FTMNhkb+ODhEgvhzqWZnFoKf4t6lV4/lzZRMKT7OFY7gVBRQKR5LqX8YDDGZwMgQ/Xb0NsCDGPFenfmstWsJMaFghd4LC6iMfGtxvLblnqGJDDrU3is+0c/f70sBSVf4IBCaXQ3XFPouAh+dZqgFy1NYymBPh4eXr6OuG8tjO7NrRU1xIkC3QVDNyKp756rNxwh1uFxP3AWr2RQDFj14ree0CkKTnIeK4QwQdZunN4V1Zc5b0ScCAwEAAaNjMGEwHQYDVR0OBBYEFMyClzyen614uGbZtRzIILlfXAnAMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUzIKXPJ6frXi4Ztm1HMgguV9cCcAwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4IBAQApUHb6jiI6BGGUDj4/vxQVHq4pvcp2XnZpCgkk55a3+L3yQfnkog5CQ/XbMhLofmw1NR+snBURiMzUDmjH40ey96X/S5M+qYTE/6eQ/CDURBBeXvAR7JfdTMeuzh4nHNKn1EeN0axfOQCkPLl4swhogeh0PqL9LTlp5nhfVkasKeit41wuuOIJkOW4AA+ZG+O6LOHWhsI6YH80m4XkHeF8nQNkcTy+bE1fKpSBICZW5RxRT8uwjIxoAKN+w0J4Zlow9G9cZVcxDtB/H14OE2ZQXmDYd9UyFcFJzcicJ3qforXTWGHYo63gV+8OT8s5x7DuvosToPtn89JR1nb8E/sx\n-----END CERTIFICATE-----\n");

        // Issuer 2: CN=DemoRootCA1, OU=EJBCA, O=SignServer Sample, C=SE
        workerSession.setWorkerProperty(7101, "VAL1.ISSUER2.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\nMIICfjCCAeegAwIBAgIIGo+E2d/oU9EwDQYJKoZIhvcNAQEFBQAwTzEUMBIGA1UEAwwLRGVtb1Jvb3RDQTExDjAMBgNVBAsMBUVKQkNBMRowGAYDVQQKDBFTaWduU2VydmVyIFNhbXBsZTELMAkGA1UEBhMCU0UwHhcNMDkxMTA5MTQ0MTIzWhcNMzQxMTEwMTQ0MTIzWjBPMRQwEgYDVQQDDAtEZW1vUm9vdENBMTEOMAwGA1UECwwFRUpCQ0ExGjAYBgNVBAoMEVNpZ25TZXJ2ZXIgU2FtcGxlMQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAm9kfNe5zQ6d/J4FShC0ud2KAX7Wso+ulcI/2zyYFUnj2QcUVZ3KEwXyDjWlFOkXX5LVbmiDMglr/iPgKeh+L1Pd4nQ3ydW+jG1a0Yxe6eyaQqaflrsIai3JXmllUMp7kTc7ylcuuNmkxiTX2vhYltqgdVdfJ29eDwBVnkmPAsNsCAwEAAaNjMGEwHQYDVR0OBBYEFIC1Yu2E2Ia344+IumPUHchd5ylLMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUgLVi7YTYhrfjj4i6Y9QdyF3nKUswDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4GBAI+eyurSlvV/W23UskU85CsPid/Hiy0cvMWtc5i+ZWQTDEyW53n1nc2yHpSBY30wUbd8p0Qbdl03Y+S/n+arItiAPqC/RZttgTfcztwSU/nWugIrgwoPltA4H582IBzO7cmJ26jGwQQsD6uCCTQSJK9xlqXQw8Uyj+N6SvE3p+wq\n-----END CERTIFICATE-----\n");

        // Issuer 3: CN=DemoRootCA2, OU=EJBCA, O=SignServer Sample, C=SE
        workerSession.setWorkerProperty(7101, "VAL1.ISSUER3.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\nMIIDPTCCAvygAwIBAgIIJgIAcQevf5UwCQYHKoZIzjgEAzBPMRQwEgYDVQQDDAtEZW1vUm9vdENBMjEOMAwGA1UECwwFRUpCQ0ExGjAYBgNVBAoMEVNpZ25TZXJ2ZXIgU2FtcGxlMQswCQYDVQQGEwJTRTAeFw0wOTExMDkxNjA5NDhaFw0zNDExMTAxNjA5NDhaME8xFDASBgNVBAMMC0RlbW9Sb290Q0EyMQ4wDAYDVQQLDAVFSkJDQTEaMBgGA1UECgwRU2lnblNlcnZlciBTYW1wbGUxCzAJBgNVBAYTAlNFMIIBtzCCASsGByqGSM44BAEwggEeAoGBAI+d9uiMBBzqdvlV3wSMdwRv/Qx2POGqh+m0M0tMYEwIGBdZHm3+QSKIDTjcLRJgCGgTXSAJPCZtp43+kWCV5iGbbemBchOCh4Oe/4IPQERlfJhyMH0gXLglG9KSbuKkqMSzaZoZk06q750KBKusKhK+mvhp08++KyXZna3p6itdAhUAntjYRJsYqqQtIt0htCGCEAHCkg8CgYA4E4VMplm16uizoUL+9erNtLI886f8pdO5vXhcQG9IpZ0J7N6M4WQy8CFzTKjRJLs27TO2gDP8BE50mMOnbRvYmGIJsQ9lZHTjUqltWh9PJ0VKF0fCwQbA3aY+v8PiHxELvami+YyBiYjE2C6b1ArKOw1QsEL0KakJcr22yWFaKgOBhQACgYEAiTsSMcEKhYCWg2ULDwD/4ueYyDcRvyoSrT7uCdGU0Y/w2wPuI+kV5RfHxjs6YLDuJsQJg6rfi3RfgmwQJVzClDfgUN12qzRbSidepg/7ipkCGk0/eyY1A99z3K+FUZm2MVgune4ywCorPUpxz6WHS7/dSWYMWtSrr92PzgnwZbKjYzBhMB0GA1UdDgQWBBRJ3xUuyl6ZroD3lFm3nw/AhCPeJTAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFEnfFS7KXpmugPeUWbefD8CEI94lMA4GA1UdDwEB/wQEAwIBhjAJBgcqhkjOOAQDAzAAMC0CFQCEGSmvJf6rxy6u7ZqY25qE7Hy21gIUPW4q++YIS2fHyu+H4Pjgnodx5zI=\n-----END CERTIFICATE-----\n");

        workerSession.reloadConfiguration(7101);
    }

    // TODO add test methods here. The name must begin with 'test'. For example:
    // public void testHello() {}

    @Test
    public void test01GetStatusOk() {
        try {
            final String status = ws.getStatus(
                    WORKER_NAME);
            assertEquals("status", "ALLOK", status);
        } catch (IllegalRequestException_Exception ex) {
            LOG.error(ex, ex);
            fail("Has test-configuration.properties been applied?");
        }
    }

    @Test
    public void test02GetStatusNonExisting() {
        try {
            final String status = ws.getStatus(NONEXISTING_WORKER);
            fail("Should have thrown exception but got status: " + status);
        } catch (IllegalRequestException_Exception ok) { //NOPMD
            // OK
        }
    }

    @Test
    public void test03IsValid() {
        try {
            final ValidationResponse response
                = ws.isValid(WORKER_NAME, CERT_XMLSIGNER4,
                ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
            LOG.debug("Response: " + toString(response));
            assertEquals("status", Status.VALID, response.getStatus());
            assertEquals("purpose",
                    ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE,
                    response.getValidCertificatePurposes());
            assertNotNull("validationDate", response.getValidationDate());
        } catch (IllegalRequestException_Exception | SignServerException_Exception ex) {
            LOG.error(ex, ex);
            fail(ex.getMessage());
        }
    }

    @Test
    public void test04IsValidNonExisting() {
        try {
            ws.isValid(NONEXISTING_WORKER, CERT_XMLSIGNER4,
                ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
            fail("Should have thrown exception");
        } catch (IllegalRequestException_Exception ex) { //NOPMD
            // OK
        } catch (SignServerException_Exception ex) {
            LOG.error(ex, ex);
            fail(ex.getMessage());
        }
    }

    @Test
    public void test99RemoveDatabase() {
        removeWorker(7101);
    }

    private String toString(ValidationResponse response) {
        final StringBuilder result = new StringBuilder();

        result.append("ValidateResponse {").append("\n\t");
        result.append("revocationReason: ").append(response.getRevocationReason()).append("\n\t");
        result.append("revocationDate: ").append(response.getRevocationDate()).append("\n\t");
        result.append("status: ").append(response.getStatus()).append("\n\t");
        result.append("statusMessage: ").append(response.getStatusMessage()).append("\n\t");
        result.append("validCertificatePurposes: ").append(response.getValidCertificatePurposes()).append("\n\t");
        result.append("validationDate: ").append(response.getValidationDate()).append("\n");

        result.append("}");
        return result.toString();
    }
}
