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
import java.util.Properties;
import javax.xml.namespace.QName;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.signserver.validationservice.common.ValidationServiceConstants;

/**
 * Test calling ValidationWSService using SignServer 3.1 WSDL.
 *
 * This tests assumes that test-configuration.properties as been applied to
 * SignServer.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ValidationWSServiceTest extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(ValidationWSServiceTest.class);

    /** Endpoint URL. */
    private static final String ENDPOINT =
            "https://localhost:8442/signserver/validationws/validationws?wsdl";

    /** Worker ID as defined in test-configuration.properties. **/
    private static final String WORKERID = "7001";

    /** A worker ID assumed to not be existing. */
    private static final String NONEXISTING_WORKERID = "1231231";

    private static final String WORKER_NAME
            = "ValidationWSServiceTest_CertValidationWorker1";
    
    private static final String NONEXISTING_WORKER = "_NonExistingWorker123_";

        /**
     * Certificate for xmlsigner4.
     * <pre>
     * Serial Number: 23:14:08:b6:eb:aa:42:dc
     *  Signature Algorithm: dsaWithSHA1
     *  Issuer: CN=DemoRootCA2, OU=EJBCA, O=SignServer Sample, C=SE
     *  Validity
     *      Not Before: Nov 10 11:22:11 2009 GMT
     *      Not After : Nov 10 11:22:11 2019 GMT
     *  Subject: CN=xmlsigner4
     * </pre>
     */
    private static final String CERT_XMLSIGNER4 =
        "MIIDADCCAsCgAwIBAgIIIxQItuuqQtwwCQYHKoZIzjgEAzBPMRQwEgYDVQQDDAtE"
        +"ZW1vUm9vdENBMjEOMAwGA1UECwwFRUpCQ0ExGjAYBgNVBAoMEVNpZ25TZXJ2ZXIg"
        +"U2FtcGxlMQswCQYDVQQGEwJTRTAeFw0wOTExMTAxMTIyMTFaFw0xOTExMTAxMTIy"
        +"MTFaMBUxEzARBgNVBAMMCnhtbHNpZ25lcjQwggG4MIIBLAYHKoZIzjgEATCCAR8C"
        +"gYEA/X9TgR11EilS30qcLuzk5/YRt1I870QAwx4/gLZRJmlFXUAiUftZPY1Y+r/F"
        +"9bow9subVWzXgTuAHTRv8mZgt2uZUKWkn5/oBHsQIsJPu6nX/rfGG/g7V+fGqKYV"
        +"DwT7g/bTxR7DAjVUE1oWkTL2dfOuK2HXKu/yIgMZndFIAccCFQCXYFCPFSMLzLKS"
        +"uYKi64QL8Fgc9QKBgQD34aCF1ps93su8q1w2uFe5eZSvu/o66oL5V0wLPQeCZ1FZ"
        +"V4661FlP5nEHEIGAtEkWcSPoTCgWE7fPCTKMyKbhPBZ6i1R8jSjgo64eK7OmdZFu"
        +"o38L+iE1YvH7YnoBJDvMpPG+qFGQiaiD3+Fa5Z8GkotmXoB7VSVkAUw7/s9JKgOB"
        +"hQACgYEA1CXfT00olSOapmZl4zT1/tUQzOzttQ/DCB8qYwH5fKD4cw1O2IutdntO"
        +"P+Pd+Q6PV6r/cckmpvO12/sMpxWOmY1oio44L8Pl76MWqKiBecAsNgxjXkXiFdJ8"
        +"llhTj9Z8vSYP8TUyY4UaITm3oZOp60eamFL93LjvpOkrDj7orXijYDBeMB0GA1Ud"
        +"DgQWBBRqEubbKMwapnZFeqgUNRFEkKGpWjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQY"
        +"MBaAFEnfFS7KXpmugPeUWbefD8CEI94lMA4GA1UdDwEB/wQEAwIGwDAJBgcqhkjO"
        +"OAQDAy8AMCwCFDnp413fYl32LXvI/FrHLxfo5hW6AhRv3xxzl07QDdL/oWCtW0rs"
        +"tmtQmg==";

    private ValidationWS ws;

    public ValidationWSServiceTest(String testName) {
        super(testName);
        setupKeystores();
    }

    /** Setup keystores for SSL. **/
    private void setupKeystores() {
        Properties config = new Properties();
        try {
            config.load(new FileInputStream(new File("../../signserver_build.properties")));
        } catch (FileNotFoundException ignored) {
            LOG.debug("No signserver_build.properties");
        } catch (IOException ex) {
            LOG.error("Not using signserver_build.properties: " + ex.getMessage());
        }
        System.setProperty("javax.net.ssl.trustStore", "../../p12/truststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword",
                config.getProperty("java.trustpassword", "changeit"));
        //System.setProperty("javax.net.ssl.keyStore", "../../p12/testadmin.jks");
        //System.setProperty("javax.net.ssl.keyStorePassword", "foo123");
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        LOG.info("Initilizing test using WS URL: " + getWsEndPointUrl());
        final QName qname
                = new QName("gen.ws.validationservice.protocol.signserver.org",
                "ValidationWSService");
        final ValidationWSService wsService = new ValidationWSService(
               new URL(getWsEndPointUrl()), qname);
        ws =  wsService.getValidationWSPort();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /** Overridden by org.signserver.test.validationws.v32.ValidationWSServiceTest */
    protected String getWsEndPointUrl() {
    	return ENDPOINT;
    }

    // TODO add test methods here. The name must begin with 'test'. For example:
    // public void testHello() {}

    public void testGetStatusOk() {
        try {
            final String status = ws.getStatus(
                    WORKER_NAME);
            assertEquals("status", "ALLOK", status);
        } catch (IllegalRequestException_Exception ex) {
            LOG.error(ex, ex);
            fail("Has test-configuration.properties been applied?");
        }
    }

    public void testGetStatusNonExisting() {
        try {
            final String status = ws.getStatus(NONEXISTING_WORKER);
            fail("Should have thrown exception");
        } catch (IllegalRequestException_Exception ok) {
            // OK
        }
    }

    public void testIsValid() {
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
        } catch (IllegalRequestException_Exception ex) {
            LOG.error(ex, ex);
            fail(ex.getMessage());
        } catch (SignServerException_Exception ex) {
            LOG.error(ex, ex);
            fail(ex.getMessage());
        }
    }

    public void testIsValidNonExisting() {
        try {
            ws.isValid(NONEXISTING_WORKER, CERT_XMLSIGNER4,
                ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
            fail("Should have thrown exception");
        } catch (IllegalRequestException_Exception ex) {
            // OK
        } catch (SignServerException_Exception ex) {
            LOG.error(ex, ex);
            fail(ex.getMessage());
        }
    }

    private String toString(ValidationResponse response) {
        final StringBuilder result = new StringBuilder();
        result.append("ValidateResponse {");
        result.append("\n\t");

        result.append("revocationReason: ");
        result.append(response.getRevocationReason());
        result.append("\n\t");

        result.append("revocationDate: ");
        result.append(response.getRevocationDate());
        result.append("\n\t");

        result.append("status: ");
        result.append(response.getStatus());
        result.append("\n\t");

        result.append("statusMessage: ");
        result.append(response.getStatusMessage());
        result.append("\n\t");

        result.append("validCertificatePurposes: ");
        result.append(response.getValidCertificatePurposes());
        result.append("\n\t");

        result.append("validationDate: ");
        result.append(response.getValidationDate());
        result.append("\n");

        result.append("}");
        return result.toString();
    }
}
