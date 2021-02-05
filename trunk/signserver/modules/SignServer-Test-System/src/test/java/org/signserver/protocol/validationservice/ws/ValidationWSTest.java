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
package org.signserver.protocol.validationservice.ws;

import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Map;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;

import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.keys.util.KeyTools;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.protocol.validationservice.ws.gen.IllegalRequestException_Exception;
import org.signserver.protocol.validationservice.ws.gen.ValidationResponse;
import org.signserver.protocol.validationservice.ws.gen.ValidationWSService;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.validationservice.common.Validation.Status;
import org.signserver.validationservice.common.ValidationServiceConstants;
import org.signserver.validationservice.server.ValidationTestUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

/**
 * TODO: Document me!
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ValidationWSTest extends ModulesTestCase {

    private static WorkerSessionRemote sSSession = null;
    private static org.signserver.protocol.validationservice.ws.gen.ValidationWS validationWS;
    private static String validCert1;
    private static String revokedCert1;
    private static String identificationCert1;

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        sSSession = ServiceLocator.getInstance().lookupRemote(WorkerSessionRemote.class);
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        KeyPair validRootCA1Keys = KeyTools.genKeys("1024", "RSA");
        X509Certificate validRootCA1 = ValidationTestUtils.genCert("CN=ValidRootCA1", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validRootCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

        KeyPair validSubCA1Keys = KeyTools.genKeys("1024", "RSA");
        X509Certificate validSubCA1 = ValidationTestUtils.genCert("CN=ValidSubCA1", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validSubCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

        KeyPair validCert1Keys = KeyTools.genKeys("1024", "RSA");

        validCert1 = new String(Base64.encode(ValidationTestUtils.genCert("CN=ValidCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false).getEncoded()));
        revokedCert1 = new String(Base64.encode(ValidationTestUtils.genCert("CN=revokedCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false).getEncoded()));
        identificationCert1 = new String(Base64.encode(ValidationTestUtils.genCert("CN=identificationCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false, X509KeyUsage.digitalSignature + X509KeyUsage.keyEncipherment).getEncoded()));
        ArrayList<X509Certificate> validChain1 = new ArrayList<>();
        // Add in the wrong order
        validChain1.add(validRootCA1);
        validChain1.add(validSubCA1);

        sSSession.setWorkerProperty(16, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.validationservice.server.ValidationServiceWorker");
        sSSession.setWorkerProperty(16, "AUTHTYPE", "NOAUTH");
        sSSession.setWorkerProperty(16, "NAME", "ValTest");
        sSSession.setWorkerProperty(16, "VAL1.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");
        sSSession.setWorkerProperty(16, "VAL1.TESTPROP", "TEST");
        sSSession.setWorkerProperty(16, "VAL1.ISSUER1.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(validChain1));

        sSSession.reloadConfiguration(16);
    }

    @Test
    public void test01TestWSStatus() throws Exception {
        String status = getValidationWS().getStatus("ValTest");
        assertNotNull(status);
        assertEquals(status, "ALLOK", status);

        status = getValidationWS().getStatus("16");
        assertNotNull(status);
        assertEquals(status, "ALLOK", status);

        try {
            getValidationWS().getStatus("asdf");
            fail();
        } catch (IllegalRequestException_Exception e) {
        }

        try {
            getValidationWS().getStatus("1717");
            fail();
        } catch (IllegalRequestException_Exception e) {
        }
    }

    @Test
    public void test02TestWSisValid() throws Exception {
        ValidationResponse res = getValidationWS().isValid("ValTest", validCert1, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        assertNotNull(res);
        assertNotNull(res.getStatusMessage());
        assertEquals(res.getStatus().toString(), Status.VALID.toString());
        assertNotNull(res.getValidationDate());
        assertEquals(res.getRevocationReason(), -1);
        assertNull(res.getRevocationDate());

        res = getValidationWS().isValid("16", validCert1, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        assertNotNull(res);
        assertNotNull(res.getStatusMessage());
        assertEquals(res.getStatus().toString(), Status.VALID.toString());
        assertNotNull(res.getValidationDate());
        assertEquals(res.getRevocationReason(), -1);
        assertNull(res.getRevocationDate());

        try {
            getValidationWS().isValid("1717", validCert1, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
            fail();
        } catch (IllegalRequestException_Exception e) {
        }
        try {
            getValidationWS().isValid("asfd", validCert1, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
            fail();
        } catch (IllegalRequestException_Exception e) {
        }

        try {
            getValidationWS().isValid("asfd", "1234", ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
            fail();
        } catch (IllegalRequestException_Exception e) {
        }

        res = getValidationWS().isValid("ValTest", revokedCert1, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        assertNotNull(res);
        assertNotNull(res.getStatusMessage());
        assertEquals(res.getStatus().toString(), Status.REVOKED.toString());
        assertNotNull(res.getValidationDate());
        assertEquals(3, res.getRevocationReason());
        assertNotNull(res.getRevocationDate());

        res = getValidationWS().isValid("ValTest", identificationCert1, ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
        assertNotNull(res);
        assertNotNull(res.getStatusMessage());
        assertEquals(res.getStatus().toString(), Status.VALID.toString()); // digitalSignature accepted
        assertNotNull(res.getValidationDate());
        assertEquals(res.getRevocationReason(), -1);
        assertNull(res.getRevocationDate());
    }

    @Test
    public void test99RemoveDatabase() {
        removeWorker(16);
    }

    private org.signserver.protocol.validationservice.ws.gen.ValidationWS getValidationWS() throws Exception {
        if (validationWS == null) {
            final SSLSocketFactory socketFactory = setupSSLKeystores();
            final String url = "https://" + getHTTPHost() + ":" + getPublicHTTPSPort() +
                               "/signserver/ValidationWSService/ValidationWS?wsdl";
            final URL resource =
                getClass().getResource("/org/signserver/protocol/validationservice/ws/ValidationWS.wsdl");
            QName qname = new QName("gen.ws.validationservice.protocol.signserver.org", "ValidationWSService");
            ValidationWSService validationWSService =
                    new ValidationWSService(resource, qname);
            validationWS = validationWSService.getValidationWSPort();

            final BindingProvider bp = (BindingProvider) validationWS;
            final Map<String, Object> requestContext = bp.getRequestContext();

            requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, url);

            if (socketFactory != null) {
                final Client client = ClientProxy.getClient(bp);
                final HTTPConduit http = (HTTPConduit) client.getConduit();
                final TLSClientParameters params = new TLSClientParameters();

                params.setSSLSocketFactory(socketFactory);
                http.setTlsClientParameters(params);
            }
        }
        return validationWS;
    }
}
