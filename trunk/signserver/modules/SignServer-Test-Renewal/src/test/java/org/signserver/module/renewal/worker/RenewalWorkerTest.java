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
package org.signserver.module.renewal.worker;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.xml.namespace.QName;
import javax.xml.ws.Endpoint;
import static junit.framework.TestCase.assertNotNull;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.util.CertTools;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.admin.cli.AdminCLI;
import org.signserver.cli.CommandLineInterface;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericPropertiesRequest;
import org.signserver.common.GenericPropertiesResponse;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.module.renewal.common.RenewalWorkerProperties;
import org.signserver.module.renewal.ejbcaws.gen.EjbcaWS;
import org.signserver.module.renewal.ejbcaws.gen.EjbcaWSService;
import org.signserver.module.renewal.ejbcaws.gen.UserDataVOWS;
import org.signserver.server.IProcessable;
import org.signserver.server.IServices;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.signers.BaseSigner;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.WorkerSessionMock;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;

/**
 * Test case for the RenewalWorker.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class RenewalWorkerTest extends AbstractTestCase {
    
    private static final String EJBCAWSURL_PREFIX
            = "http://localhost:8111/ejbca";
    private static final String EJBCAWSURL_SUFFIX
            = "/ejbcaws/ejbcaws";
    private static final String EJBCAWSURL_SUFFIX_WSDL
            = "/ejbcaws/ejbcaws?wsdl";

    public static final int SIGNERID_6102 = 6102;
    public static final String SIGNER_6102 = "Signer_6102";
    public static final String SIGNER_6102_ENDENTITY = "Signer_6102_endentity";
    public static final int CRYPTOWORKER_6200_ID = 6200;
    public static final String CRYPTOWORKER_6200 = "CryptoToken_6200";
    private static final int RENEWALSERVICE_ID = 6109;
    private static final String RENEWALSERVICE_NAME = "RenewalService9";
    
    public static final String DEFAULT_KEYALG = "RSA";
    public static final String DEFAULT_KEYSPEC = "2048";

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(RenewalWorkerTest.class);

    private static final int WORKERID = 6101;
    private static final String WORKERNAME = "RenewalWorker_6101";

    private Endpoint ejbcaEndpoint;
    private MockEjbcaWS mockEjbcaWs;
    private EjbcaWS ejbcaws;
    
    private static final String SIGN_CERT = "MIIEkTCCAnmgAwIBAgIIeCvAS5OwAJswDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzEyMTU1NVoXDTIxMDUyNDEyMTU1NVowSjEUMBIGA1UEAwwLVFMgU2lnbmVyIDExEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnT38GG8i/bGnuFMwnOdg+caHMkdPBacRdBaIggwMPfE50SOZ2TLrDEHJotxYda7HS0+tX5dIcalmEYCls/ptHzO5TQpqdRTuTqxp5cMA379yhD0OqTVNAmHrvPj9IytktoAtB/xcjwkRTHagaCmg5SWNcLKyVUct7nbeRA5yDSJQsCAEGHNZbJ50vATg1DQEyKT87GKfSBsclA0WIIIHMt8/SRhpsUZxESayU6YA4KCxVtexF5x+COLB6CzzlRG9JA8WpX9yKgIMsMDAscsJLiLPjhET5hwAFm5ZRfQQG9LI06QNTGqukuTlDbYrQGAUR5ZXW00WNHfgS00CjUCu0QIDAQABo3gwdjAdBgNVHQ4EFgQUOF0FflO2G+IN6c92pCNlPoorGVwwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBADELkeIO9aiKjS/GaBUUhMr+k5UbVeK69WapU+7gTsWwa9D2vAOhAkfQ1OcUJoZaminv8pcNfo1Ey5qLtxBCmUy1fVomVWOPl6u1w8B6uYgE608hi2bfx28uIeksqpdqUX0Qf6ReUyl+FOh4xNrsyaF81TrIKt8ekq0iD+YAtT/jqgv4bUvs5fgIms4QOXgMUzNAP7cPU44KxcmR5I5Uy/Ag82hGIz64hZmeIDT0X59kbQvlZqFaiZvYOikoZSFvdM5kSVfItMgp7qmyLxuM/WaXqJWp6Mm+8ZZmcECugd4AEpE7xIiB7M/KEe+X4ItBNTKdAoaxWa+yeuYS7ol9rHt+Nogelj/06ZRQ0x03UqC7uKpgYAICjQEXIjcZofWSTh9KzKNfS1sQyIQ6yNTT2VMdYW9JC2OLKPV4AEJuBw30X8HOciJRRXOq9KRrIA2RSiaC5/3oAYscWuo31Fmj8CWQknXAIb39gPuZRwGOJbi1tUu2zmRsUNJfAe3hnvk+uxhnyp2vKB2KN5/VQgisx+8doEK/+Nbj/PPG/zASKimWG++5m0JNY4chIfR43gDDcF+4INof/8V84wbvUF+TpvP/mYM8wC9OkUyRvzqv9vjWOncCdbdjCuqPxDItwm9hhr+PbxsMaBes9rAiV9YT1FnpA++YpCufveFCQPDbCTgJ";
    private static final String SIGN_CERT_CHAIN = "MIIEkTCCAnmgAwIBAgIIeCvAS5OwAJswDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzEyMTU1NVoXDTIxMDUyNDEyMTU1NVowSjEUMBIGA1UEAwwLVFMgU2lnbmVyIDExEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnT38GG8i/bGnuFMwnOdg+caHMkdPBacRdBaIggwMPfE50SOZ2TLrDEHJotxYda7HS0+tX5dIcalmEYCls/ptHzO5TQpqdRTuTqxp5cMA379yhD0OqTVNAmHrvPj9IytktoAtB/xcjwkRTHagaCmg5SWNcLKyVUct7nbeRA5yDSJQsCAEGHNZbJ50vATg1DQEyKT87GKfSBsclA0WIIIHMt8/SRhpsUZxESayU6YA4KCxVtexF5x+COLB6CzzlRG9JA8WpX9yKgIMsMDAscsJLiLPjhET5hwAFm5ZRfQQG9LI06QNTGqukuTlDbYrQGAUR5ZXW00WNHfgS00CjUCu0QIDAQABo3gwdjAdBgNVHQ4EFgQUOF0FflO2G+IN6c92pCNlPoorGVwwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBADELkeIO9aiKjS/GaBUUhMr+k5UbVeK69WapU+7gTsWwa9D2vAOhAkfQ1OcUJoZaminv8pcNfo1Ey5qLtxBCmUy1fVomVWOPl6u1w8B6uYgE608hi2bfx28uIeksqpdqUX0Qf6ReUyl+FOh4xNrsyaF81TrIKt8ekq0iD+YAtT/jqgv4bUvs5fgIms4QOXgMUzNAP7cPU44KxcmR5I5Uy/Ag82hGIz64hZmeIDT0X59kbQvlZqFaiZvYOikoZSFvdM5kSVfItMgp7qmyLxuM/WaXqJWp6Mm+8ZZmcECugd4AEpE7xIiB7M/KEe+X4ItBNTKdAoaxWa+yeuYS7ol9rHt+Nogelj/06ZRQ0x03UqC7uKpgYAICjQEXIjcZofWSTh9KzKNfS1sQyIQ6yNTT2VMdYW9JC2OLKPV4AEJuBw30X8HOciJRRXOq9KRrIA2RSiaC5/3oAYscWuo31Fmj8CWQknXAIb39gPuZRwGOJbi1tUu2zmRsUNJfAe3hnvk+uxhnyp2vKB2KN5/VQgisx+8doEK/+Nbj/PPG/zASKimWG++5m0JNY4chIfR43gDDcF+4INof/8V84wbvUF+TpvP/mYM8wC9OkUyRvzqv9vjWOncCdbdjCuqPxDItwm9hhr+PbxsMaBes9rAiV9YT1FnpA++YpCufveFCQPDbCTgJ;MIIFfzCCA2egAwIBAgIIMk1BOK8CwTwwDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzA4MTQyN1oXDTM2MDUyNzA4MTQyN1owTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgblgjTTkMp1QAhgWDprhvqE9zX1Ux/A/RTOu4G4f6CTkd6JEEkbdKZv+CKv4cRoVCtfO3wnOokFRw/1JMmHHiQ1Z//uDoDjo8jk8nek0ArFE9R5NT02wMJCQa/mP1wU9ZSl1tx3jQRUFB+rTNeCcPTft+1FL7UjYMdkRzl261IOlmXzDMA+EYIGJ2c2wYhOv2DqfQygNz5GOf0EFqlQZIt/pzopSS+0K8mNb53ROhg9GJujwzugSH5Z+r0fsVHbCV0QUkZBfkRo9KMcdaDEPa8xpYTjsFPqU6RcnGkVABhn8OS8SIWw2re1f+htj6p9EGbk1m0I9pWGBA9ktWnrqlqDXV+tEhhh1O4f+LHieoxiscrF7RXxlYqyam6oabfXsX3VAC0M1UkwIciE8wA1Sj/+dgoSMqvEDNDfwpEYt6l8Z8czDTWDi7MM2u5VY0nP3+A+PepKrOtrdaGSP396f4a7A3un1o6nQWHsyWQ7kc8GIn8zN5nykQaghGyYlHHYe1XUSPtHmxjbdsyztrkIis3cfjFne0XgPAiQuYx3T/B+po9BhGIUwCV0Qi/gWVN6NkydsbzMeRXELQYyK+lHgIGiEaBzQRRtXbnB+wQXi2IacJNdKqICwDsl/PvvcZI9ZV6pB/KIzB+8IJm0CLY24K0OXJs3Bqij8gmpvbI+o0wUCAwEAAaNjMGEwHQYDVR0OBBYEFCB6Id7orbsCqPtxWKQJYrnYWAWiMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUIHoh3uituwKo+3FYpAliudhYBaIwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQAxFvpOZF6Kol48cQeKWQ48VAe+h5dmyKMfDLDZX51IRzfKKsHLpFPxzGNw4t9Uv4YOR0CD9z81dR+c93t1lwwIpKbx9Qmq8jViHEHKYD9FXThM+cVpsT25pg35m3ONeUX/b++l2d+2QNNTWMvdsCtaQdybZqbYFIk0IjPwLLqdsA8Io60kuES4JnQahPdLkfm70rgAdmRDozOfSDaaWHY20DovkfvKUYjPR6MGAPD5w9dEb4wp/ZjATblyZnH+LTflwfftUAonmAw46E0Zgg143sO6RfOOnbwjXEc+KXd/KQ6kTQ560mlyRd6q7EIDYRfD4n4agKV2R5gvVPhMD0+IK7kagqKNfWa9z8Ue2N3MedyWnb9wv4wC69qFndGaIfYADkUykoOyLsVVteJ70PVJPXO7s66LucfD2R0wo2MpuOYCsTOm7HHS+uZ9VjHl2qQ0ZQG89Xn+AXnzPbk1INe2z0lq3hzCW5DTYBKsJEexErzMpLwiEqUYJUfR9EeCM8UPMtLSqz1utdPoIYhULGzt5lSJEpMHMbquYfWJxQiKCbvfxQsP5dLUMEIqTgjNdo98OlM7Z7zjYH9Kimz3wgAKSAIoQZr7Oy1dMHO5GK4jBtZ8wgsyyQ6DzQQ7R68XFVKarIW8SATeyubAP+WjdMwk/ZXzsDjMZEtENaBXzAefYA==";
    private static final String KEY_DATA = "AAABJjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ09/BhvIv2xp7hTMJznYPnGhzJHTwWnEXQWiIIMDD3xOdEjmdky6wxByaLcWHWux0tPrV+XSHGpZhGApbP6bR8zuU0KanUU7k6saeXDAN+/coQ9Dqk1TQJh67z4/SMrZLaALQf8XI8JEUx2oGgpoOUljXCyslVHLe523kQOcg0iULAgBBhzWWyedLwE4NQ0BMik/Oxin0gbHJQNFiCCBzLfP0kYabFGcREmslOmAOCgsVbXsRecfgjiwegs85URvSQPFqV/cioCDLDAwLHLCS4iz44RE+YcABZuWUX0EBvSyNOkDUxqrpLk5Q22K0BgFEeWV1tNFjR34EtNAo1ArtECAwEAAQAABMEwggS9AgEAMA0GCSqGSIb3DQEBAQUABIIEpzCCBKMCAQACggEBAJ09/BhvIv2xp7hTMJznYPnGhzJHTwWnEXQWiIIMDD3xOdEjmdky6wxByaLcWHWux0tPrV+XSHGpZhGApbP6bR8zuU0KanUU7k6saeXDAN+/coQ9Dqk1TQJh67z4/SMrZLaALQf8XI8JEUx2oGgpoOUljXCyslVHLe523kQOcg0iULAgBBhzWWyedLwE4NQ0BMik/Oxin0gbHJQNFiCCBzLfP0kYabFGcREmslOmAOCgsVbXsRecfgjiwegs85URvSQPFqV/cioCDLDAwLHLCS4iz44RE+YcABZuWUX0EBvSyNOkDUxqrpLk5Q22K0BgFEeWV1tNFjR34EtNAo1ArtECAwEAAQKCAQBwMW7zXDDiROU/3pOcEHegIGgMltaqWNdaNk22RLRjaf/v2nAGio8tUq91NbUkWs22TaaNwxqchtrd+CXDMha0IarAboMhAQs8NUbl+mpgO3CRLCOO1goZfha+4gV0F50nnnMC9KxyHm0qWqX/TFyRw2aVF9uofz4lnMjgVFJKTaQkm1v6Odmhb/IqNQmjbmGHsfKcJHFwy667euzJkyr2Nh/9CBuIjmS4/8NsqdnXjugp5pBVvu7qoS7GlU5FgXohEV80OdsxLNVVw86K6FC/9+U6f7qoeULS9k0sGgH26UNUluiPPqXLgHj/HlGHWOYPqqWJwS3vL9sAwyULto3VAoGBAO5bsl/5BEGTUdNNEORTEaqT1GA23HjhlBwFOoJMeHzxoEyahPKwvyrDKB5LpIMu7Ll+YfIpPDPnZn5h11zcuYAzPWFY9oLYzq50lrHh0i7IgJ+4jPRtkdD2IcR52g+YpeczxHqWpZZCM2Um3fmAJBrkE8pGxl1lKw2G8I3yYOCrAoGBAKjhVmXlDaJfTJP5080+pP0WbZAqifI7NK63bKeLkzgSppOUus11pHmRLqB9Pm/+jVAssFsqOp7QptUYzt6SBgWT/QF1gFkp8oHVWBp6/WpVu0xInB94QWs99y/b5oHRjJOtYiodtd6pLyEM29Y/3iy/rseXTPuFlcnS1HBc50ZzAoGAOOtIw0ZRz98AMTc8C2oS0+sNUhSHvY4QskhFWowsUZnZr7FOgi3W2L1VvTZPCMyR1xHpDczvBW4CubdfmFtVKNoTlEWMSF7BrENHIR9N88IJhRqq/kuUAJRmJ+b5PbQ0GevwxV1oGWOhpkwLweLpvEout6UDBZZ9G3PXye3RWJUCgYBTp8v0jZJDbJGye36/nNh9xi5fy7Kpm0ptgc8A79LtY8/AK1ydijj/PzuppGDZeW7m2DxD7Jc9NH5v8OoItqzk9nnNzzbU9EJ8rgIGnAYMNouhLhaoQBmn1fosavG0POk1/h0yX6VHtubxqDz91IVqBUm+9OPddD7OyvEQ9/RYoQKBgQCOlHxw0uHMma/P/4Z8nyjyRF3vqzn/UpOMc1Z402yYK9ZcR7zPFHlrHC/6FACJJQpwnzDj24fNAJFrwl3usohj08hGn6NF7nTi8v4pFZHnt5pUIfXA4e4QIVO00Tv+GK+BMl3F+jsGUJK/TsccyoMht25o74oJDD6a7IcVTRnxTA==";


    @Override
    protected void setUp() throws Exception {
        super.setUp();

        mockEjbcaWs = new MockEjbcaWS();
        ejbcaEndpoint = Endpoint.publish(EJBCAWSURL_PREFIX + EJBCAWSURL_SUFFIX,
                mockEjbcaWs);

        final EjbcaWSService service = new EjbcaWSService(
                new URL(EJBCAWSURL_PREFIX + EJBCAWSURL_SUFFIX_WSDL),
                new QName("http://ws.protocol.core.ejbca.org/",
                "EjbcaWSService"));
        ejbcaws = service.getEjbcaWSPort();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();

        ejbcaEndpoint.stop();
        removeSigners();
        removeTempFiles();
    }

    public void test01ejbcaWSMockWorking() throws Exception {
        assertTrue(ejbcaws.isAuthorized("Hej"));
    }

    /**
     * Tests renewal of key and certificate for a worker.
     * @throws Exception
     */
    public void test02renewalFirstTime() throws Exception {        
        // Setup workers
        addWorkers();

        // Setup EJBCA end entity
        mockSetupEjbcaSearchResult();
     
        // Test starts here
        doRenewalFirstTime();
    }

    private void doRenewalFirstTime() throws Exception {
        final Properties reqProperties = new Properties();
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_WORKER,
                SIGNER_6102);
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_AUTHCODE,
                "foo123");
        final GenericPropertiesRequest request = new GenericPropertiesRequest(
                reqProperties);
        GenericPropertiesResponse response
                = (GenericPropertiesResponse) getProcessSession().process(
                    new WorkerIdentifier(WORKERID), request, new RemoteRequestContext());

        // OK result
        final String message = response.getProperties().getProperty(RenewalWorkerProperties.RESPONSE_MESSAGE);
        LOG.info("Response message: " + message);
        assertEquals("message: " + message, RenewalWorkerProperties.RESPONSE_RESULT_OK,
                response.getProperties().getProperty(
                RenewalWorkerProperties.RESPONSE_RESULT));

        // Requested certificate
        assertTrue("should have requested certificate",
                mockEjbcaWs.isPkcs10RequestCalled());
        
        // Check that the right DN is included
        assertEquals("Requested DN", "CN=" + SIGNER_6102_ENDENTITY + ",C=SE", mockEjbcaWs.getLastPKCS10().getRequestDN());
        
        // Should not be any NEXTCERTSIGNKEY
        assertNull("no NEXTCERTSIGNKEY", getWorkerSession().getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("NEXTCERTSIGNKEY"));

        // Should be an DEFAULTKEY
        assertNotNull("DEFAULTKEY", getWorkerSession().getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("DEFAULTKEY"));
        
        // Should have certificate and chain
        final X509Certificate cert = (X509Certificate) getWorkerSession()
                .getSignerCertificate(new WorkerIdentifier(SIGNERID_6102));
        assertNotNull(cert);
        final List<java.security.cert.Certificate> chain
                = getWorkerSession().getSignerCertificateChain(new WorkerIdentifier(SIGNERID_6102));
        assertNotNull("chain", chain);
        assertFalse("chain not empty", chain.isEmpty());
        System.out.println("chain: " + chain);
        System.out.println("cert: " + cert);
        
        assertTrue("chain contains cert", chain.contains(cert));
    }

    /** 
     * Test Renewal without key generation (ie when NEXTCERTSIGNKEY exists)
     *
     * Config: NEXTCERTSIGNKEY
     * Request: -
     * Result: Only DEFAULTKEY (containing value from NEXTCERTSIGNKEY)
     * @throws java.lang.Exception
     */
    public void test03renewalExistingNextCertSignKey() throws Exception {
        // Setup workers
        addWorkers();

        // Setup EJBCA end entity
        mockSetupEjbcaSearchResult();

        // Generate a new key
        final String nextCertSignAlias = "test03_keyalias";
        getWorkerSession().generateSignerKey(new WorkerIdentifier(SIGNERID_6102), DEFAULT_KEYALG,
                DEFAULT_KEYSPEC, nextCertSignAlias, "foo123".toCharArray());
        getWorkerSession().setWorkerProperty(SIGNERID_6102, "NEXTCERTSIGNKEY",
                nextCertSignAlias);
        getWorkerSession().reloadConfiguration(SIGNERID_6102);
        assertEquals("New nextcertsignkey alias", nextCertSignAlias,
                getWorkerSession().getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("NEXTCERTSIGNKEY"));


        // Test starts here
        final Properties reqProperties = new Properties();
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_WORKER,
                SIGNER_6102);
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_AUTHCODE,
                "foo123");
        final GenericPropertiesRequest request = new GenericPropertiesRequest(
                reqProperties);
        GenericPropertiesResponse response
                = (GenericPropertiesResponse) getProcessSession().process(
                    new WorkerIdentifier(WORKERID), request, new RemoteRequestContext());

        // OK result
        LOG.info("Response message: " + response.getProperties().getProperty(
                RenewalWorkerProperties.RESPONSE_MESSAGE));
        assertEquals(RenewalWorkerProperties.RESPONSE_RESULT_OK,
                response.getProperties().getProperty(
                RenewalWorkerProperties.RESPONSE_RESULT));

        // Requested certificate
        assertTrue("should have requested certificate",
                mockEjbcaWs.isPkcs10RequestCalled());

        // Should have certificate and chain
        final X509Certificate cert = (X509Certificate) getWorkerSession()
                .getSignerCertificate(new WorkerIdentifier(SIGNERID_6102));
        assertNotNull(cert);
        final List<java.security.cert.Certificate> chain
                = getWorkerSession().getSignerCertificateChain(new WorkerIdentifier(SIGNERID_6102));
        assertNotNull(chain);
        assertTrue(chain.contains(cert));

        // Should not be any NEXTCERTSIGNKEY
        assertNull(getWorkerSession().getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("NEXTCERTSIGNKEY"));

        // Should be an DEFAULTKEY
        assertNotNull(getWorkerSession().getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("DEFAULTKEY"));


        // DEFAULTKEY should now have the right alias
        assertEquals(nextCertSignAlias,  getWorkerSession()
                .getCurrentWorkerConfig(SIGNERID_6102).getProperty("DEFAULTKEY"));
    }

    /**
     * Test renewal without key generation (ie when NEXTCERTSIGNKEY exists) but
     * for DEFAULTKEY requested in request.
     *
     * Config: NEXTCERTSIGNKEY, DEFAULTKEY
     * Request: FORDEFAULTKEY
     * Result: NEXTCERTSIGNKEY, DEFAULTKEY
     * @throws java.lang.Exception
     */
    public void test04renewalExistingNextCertSignKeyForDefaultKey() throws Exception {
        // Setup workers
        addWorkers();

        // Setup EJBCA end entity
        mockSetupEjbcaSearchResult();

        // Generate a new key
        final String nextCertSignAlias = "test4_keyalias2";
        final String defaultKeyAlias = "test04_keyalias";
        getWorkerSession().generateSignerKey(new WorkerIdentifier(SIGNERID_6102), DEFAULT_KEYALG,
                DEFAULT_KEYSPEC, defaultKeyAlias, "foo123".toCharArray());
        getWorkerSession().setWorkerProperty(SIGNERID_6102, "DEFAULTKEY",
                defaultKeyAlias);
        getWorkerSession().setWorkerProperty(SIGNERID_6102, "NEXTCERTSIGNKEY",
                nextCertSignAlias);
        getWorkerSession().reloadConfiguration(SIGNERID_6102);
        assertEquals("New defaultkey alias", defaultKeyAlias,
                getWorkerSession().getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("DEFAULTKEY"));


        // Test starts here
        final Properties reqProperties = new Properties();
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_FORDEFAULTKEY,
                RenewalWorkerProperties.REQUEST_FORDEFAULTKEY_TRUE);
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_WORKER,
                SIGNER_6102);
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_AUTHCODE,
                "foo123");
        final GenericPropertiesRequest request = new GenericPropertiesRequest(
                reqProperties);
        GenericPropertiesResponse response
                = (GenericPropertiesResponse) getProcessSession().process(
                    new WorkerIdentifier(WORKERID), request, new RemoteRequestContext());

        // OK result
        LOG.info("Response message: " + response.getProperties().getProperty(
                RenewalWorkerProperties.RESPONSE_MESSAGE));
        assertEquals(RenewalWorkerProperties.RESPONSE_RESULT_OK,
                response.getProperties().getProperty(
                RenewalWorkerProperties.RESPONSE_RESULT));

        // Requested certificate
        assertTrue("should have requested certificate",
                mockEjbcaWs.isPkcs10RequestCalled());

        // Should have certificate and chain
        final X509Certificate cert = (X509Certificate) getWorkerSession()
                .getSignerCertificate(new WorkerIdentifier(SIGNERID_6102));
        assertNotNull(cert);
        final List<java.security.cert.Certificate> chain
                = getWorkerSession().getSignerCertificateChain(new WorkerIdentifier(SIGNERID_6102));
        assertNotNull(chain);
        assertTrue(chain.contains(cert));

        // Should still be a NEXTCERTSIGNKEY
        assertEquals(nextCertSignAlias,
                getWorkerSession().getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("NEXTCERTSIGNKEY"));

        // Should be an DEFAULTKEY
        assertNotNull(getWorkerSession().getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("DEFAULTKEY"));

        // DEFAULTKEY should not have changed
        assertEquals(defaultKeyAlias,  getWorkerSession()
                .getCurrentWorkerConfig(SIGNERID_6102).getProperty("DEFAULTKEY"));
    }

    /**
     * Test renewal without key generation (for DEFAULTKEY requested in request).
     *
     * Config: DEFAULTKEY
     * Request: FORDEFAULTKEY
     * Result: DEFAULTKEY
     * @throws java.lang.Exception
     */
    public void test05renewalExistingKeyForDefaultKey() throws Exception {
        // Setup workers
        addWorkers();

        // Setup EJBCA end entity
        mockSetupEjbcaSearchResult();

        // Generate a new key
        final String defaultKeyAlias = "test05_keyalias";
        getWorkerSession().generateSignerKey(new WorkerIdentifier(SIGNERID_6102), DEFAULT_KEYALG,
                DEFAULT_KEYSPEC, defaultKeyAlias, "foo123".toCharArray());
        getWorkerSession().setWorkerProperty(SIGNERID_6102, "DEFAULTKEY",
                defaultKeyAlias);
        getWorkerSession().reloadConfiguration(SIGNERID_6102);
        assertEquals("New defaultkey alias", defaultKeyAlias,
                getWorkerSession().getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("DEFAULTKEY"));


        // Test starts here
        final Properties reqProperties = new Properties();
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_FORDEFAULTKEY,
                RenewalWorkerProperties.REQUEST_FORDEFAULTKEY_TRUE);
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_WORKER,
                SIGNER_6102);
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_AUTHCODE,
                "foo123");
        final GenericPropertiesRequest request = new GenericPropertiesRequest(
                reqProperties);
        GenericPropertiesResponse response
                = (GenericPropertiesResponse) getProcessSession().process(
                    new WorkerIdentifier(WORKERID), request, new RemoteRequestContext());

        // OK result
        LOG.info("Response message: " + response.getProperties().getProperty(
                RenewalWorkerProperties.RESPONSE_MESSAGE));
        assertEquals(RenewalWorkerProperties.RESPONSE_RESULT_OK,
                response.getProperties().getProperty(
                RenewalWorkerProperties.RESPONSE_RESULT));

        // Requested certificate
        assertTrue("should have requested certificate",
                mockEjbcaWs.isPkcs10RequestCalled());

        // Should have certificate and chain
        final X509Certificate cert = (X509Certificate) getWorkerSession()
                .getSignerCertificate(new WorkerIdentifier(SIGNERID_6102));
        assertNotNull(cert);
        final List<java.security.cert.Certificate> chain
                = getWorkerSession().getSignerCertificateChain(new WorkerIdentifier(SIGNERID_6102));
        assertNotNull(chain);
        assertTrue(chain.contains(cert));

        // DEFAULTKEY should not have changed
        assertEquals(defaultKeyAlias,  getWorkerSession()
                .getCurrentWorkerConfig(SIGNERID_6102).getProperty("DEFAULTKEY"));
    }

    /**
     * Test failure: No EJBCA end entity.
     * @throws java.lang.Exception
     */
    public void test06failureNoEJBCAEndEntity() throws Exception {
        // Setup workers
        addWorkers();

        // Set non-existing end entity
        getWorkerSession().setWorkerProperty(SIGNERID_6102, "RENEWENDENTITY",
                "_non_existing_endentity_");
        getWorkerSession().reloadConfiguration(SIGNERID_6102);

        // Setup EJBCA end entity
        mockSetupEjbcaSearchResult();

        // Should not be any NEXTCERTSIGNKEY
        assertNull(getWorkerSession().getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("NEXTCERTSIGNKEY"));

        // Store DEFAULTKEY value
        final String defaultKey = getWorkerSession().getCurrentWorkerConfig(
                SIGNERID_6102).getProperty("DEFAULTKEY");

        // Test starts here
        final Properties reqProperties = new Properties();
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_WORKER,
                SIGNER_6102);
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_AUTHCODE,
                "foo123");
        final GenericPropertiesRequest request = new GenericPropertiesRequest(
                reqProperties);
        GenericPropertiesResponse response
                = (GenericPropertiesResponse) getProcessSession().process(
                    new WorkerIdentifier(WORKERID), request, new RemoteRequestContext());

        // OK result
        LOG.info("Response message: " + response.getProperties().getProperty(
                RenewalWorkerProperties.RESPONSE_MESSAGE));
        assertEquals("Should be failure",
                RenewalWorkerProperties.RESPONSE_RESULT_FAILURE,
                response.getProperties().getProperty(
                RenewalWorkerProperties.RESPONSE_RESULT));

        // Should now be a NEXTCERTSIGNKEY
        assertNotNull(getWorkerSession().getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("NEXTCERTSIGNKEY"));

        // Should be the same DEFAULTKEY
        assertEquals(defaultKey, getWorkerSession()
                .getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("DEFAULTKEY"));
    }

    /**
     * Test failure: Authentication denied
     * @throws java.lang.Exception
     */
    public void test07failureEJBCAAuthDenied() throws Exception {
        // Setup workers
        addWorkers();

        // Setup EJBCA end entity
        mockSetupEjbcaSearchResult();

        // Set authentication to fail
        mockEjbcaWs.setAuthenticationFail(true);

        // Should not be any NEXTCERTSIGNKEY
        assertNull(getWorkerSession().getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("NEXTCERTSIGNKEY"));

        // Store DEFAULTKEY value
        final String defaultKey = getWorkerSession().getCurrentWorkerConfig(
                SIGNERID_6102).getProperty("DEFAULTKEY");

        // Test starts here
        final Properties reqProperties = new Properties();
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_WORKER,
                SIGNER_6102);
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_AUTHCODE,
                "foo123");
        final GenericPropertiesRequest request = new GenericPropertiesRequest(
                reqProperties);
        GenericPropertiesResponse response
                = (GenericPropertiesResponse) getProcessSession().process(
                    new WorkerIdentifier(WORKERID), request, new RemoteRequestContext());

        // OK result
        LOG.info("Response message: " + response.getProperties().getProperty(
                RenewalWorkerProperties.RESPONSE_MESSAGE));
        assertEquals("Should be failure",
                RenewalWorkerProperties.RESPONSE_RESULT_FAILURE,
                response.getProperties().getProperty(
                RenewalWorkerProperties.RESPONSE_RESULT));

        // Should now be a NEXTCERTSIGNKEY
        assertNotNull(getWorkerSession().getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("NEXTCERTSIGNKEY"));

        // Should be the same DEFAULTKEY
        assertEquals(defaultKey, getWorkerSession()
                .getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("DEFAULTKEY"));
    }

    /**
     * Tests renewal of key and certificate for a worker.
     * @throws Exception
     */
    public void test08truststoreTypeJKS() throws Exception {
        final String truststoreType = "JKS";

        // Setup workers
        addRenewalWorker(WORKERID, WORKERNAME, truststoreType);
        addSigner(SIGNERID_6102, SIGNER_6102, SIGNER_6102_ENDENTITY);

        // Setup EJBCA end entity
        mockSetupEjbcaSearchResult();

        doRenewalFirstTime();
    }

    /**
     * Tests renewal using a PEM file (no trustore password should be used)
     * @throws Exception
     */
    public void test09truststoreTypePEM() throws Exception {
    	
    	// Setup workers
    	addRenewalWorkerWithPEM(WORKERID, WORKERNAME);
    	addSigner(SIGNERID_6102, SIGNER_6102, SIGNER_6102_ENDENTITY);
    	
    	// Setup EJBCA end entitity
    	mockSetupEjbcaSearchResult();
    	
    	doRenewalFirstTime();
    }
    
    /**
     * Tests renewal using a PEM file in TRUSTSTOREVALUE property.
     * @throws Exception
     */
    public void test10truststoreTypeInlinePEM() throws Exception {
    	
    	// Setup workers
    	addRenewalWorkerWithInlinePEM(WORKERID, WORKERNAME);
    	addSigner(SIGNERID_6102, SIGNER_6102, SIGNER_6102_ENDENTITY);
    	
    	// Setup EJBCA end entitity
    	mockSetupEjbcaSearchResult();
    	
    	doRenewalFirstTime();
    }
    
    /**
     * Tests renewal using a JKS file in TRUSTSTOREVALUE property.
     * @throws Exception
     */
    public void test10truststoreTypeInlineJKS() throws Exception {
    	
    	// Setup workers
    	addRenewalWorkerWithInlineJKS(WORKERID, WORKERNAME);
    	addSigner(SIGNERID_6102, SIGNER_6102, SIGNER_6102_ENDENTITY);
    	
    	// Setup EJBCA end entitity
    	mockSetupEjbcaSearchResult();
    	
    	doRenewalFirstTime();
    }
    
    
    /**
     * Test that by default explicit ECC parameters are set to false.
     * 
     * @throws Exception
     */
    public void test10NoECCExplicit() throws Exception {
        final GlobalConfigurationSessionMock conf = new GlobalConfigurationSessionMock();
        final MockWorkerSession workerSession = new MockWorkerSession();
        
        addRenewalWorkerMock(conf, workerSession, 6110, "RenewalWorkerMock");
        addSignerMock(conf, workerSession, SIGNERID_6102, SIGNER_6102);
        
        // Test starts here
        final Properties reqProperties = new Properties();
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_WORKER,
                SIGNER_6102);
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_AUTHCODE,
                "foo123");
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_FORDEFAULTKEY, "true");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(reqProperties);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            SignatureResponse response
                    = (SignatureResponse) workerSession.process(ModulesTestCase.createAdminInfo(),
                        new WorkerIdentifier(6110), new SignatureRequest(1010, requestData, responseData), new RequestContext(true));
            assertNotNull(response);
            assertFalse("Explicit ECC parameters not set", workerSession.explicitEccParametersSet);
        }
    }
    
    /**
     * Test that setting explicit ECC parameters to true on the worker results in calling
     * getCertificateRequest with the parameter set to true.
     * 
     * @throws Exception
     */
    public void test11TrueECCExplicit() throws Exception {
        final GlobalConfigurationSessionMock conf = new GlobalConfigurationSessionMock();
        final MockWorkerSession workerSession = new MockWorkerSession();
        
        addRenewalWorkerMock(conf, workerSession, 6110, "RenewalWorkerMock");
        addSignerMock(conf, workerSession, SIGNERID_6102, SIGNER_6102);
        
        workerSession.setWorkerProperty(SIGNERID_6102, WorkerConfig.PROPERTY_EXPLICITECC, "true");
        workerSession.reloadConfiguration(SIGNERID_6102);
        
        // Test starts here
        final Properties reqProperties = new Properties();
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_WORKER,
                SIGNER_6102);
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_AUTHCODE,
                "foo123");
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_FORDEFAULTKEY, "true");
        
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(reqProperties);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            SignatureResponse response
                    = (SignatureResponse) workerSession.process(ModulesTestCase.createAdminInfo(),
                        new WorkerIdentifier(6110), new SignatureRequest(1010, requestData, responseData), new RequestContext(true));
            assertNotNull(response);
            assertTrue("Explicit ECC parameters set", workerSession.explicitEccParametersSet);
        }
    }

    /**
     * Test that setting explicit ECC parameters to false on the worker results in calling
     * getCertificateRequest with the parameter set to false.
     * 
     * @throws Exception
     */
    public void test12FalseECCExplicit() throws Exception {
        final GlobalConfigurationSessionMock conf = new GlobalConfigurationSessionMock();
        final MockWorkerSession workerSession = new MockWorkerSession();
        
        addRenewalWorkerMock(conf, workerSession, 6110, "RenewalWorkerMock");
        addSignerMock(conf, workerSession, SIGNERID_6102, SIGNER_6102);
        
        workerSession.setWorkerProperty(SIGNERID_6102, WorkerConfig.PROPERTY_EXPLICITECC, "false");
        workerSession.reloadConfiguration(SIGNERID_6102);
        
        // Test starts here
        final Properties reqProperties = new Properties();
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_WORKER,
                SIGNER_6102);
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_AUTHCODE,
                "foo123");
        reqProperties.setProperty(RenewalWorkerProperties.REQUEST_FORDEFAULTKEY, "true");
        
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(reqProperties);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            SignatureResponse response
                    = (SignatureResponse) workerSession.process(ModulesTestCase.createAdminInfo(),
                        new WorkerIdentifier(6110), new SignatureRequest(1010, requestData, responseData), new RequestContext(true));
            assertNotNull(response);
            assertFalse("Explicit ECC parameters not set", workerSession.explicitEccParametersSet);
        }
    }
    
    /**
     * Tests renewal of key and certificate for a worker using CLI.
     * @throws Exception
     */
    public void test20renewalUsingCLI() throws Exception {        
        // Setup workers
        addWorkers();

        // Setup EJBCA end entity
        mockSetupEjbcaSearchResult();
     
        // Test starts here
        doRenewalFirstTimeUsingCLI();
    }
    
    /**
     * Tests renewal of key and certificate for a worker with a JKS crypto token.
     * @throws Exception
     */
    public void test21truststoreTypeJKSWithJKSRenewee() throws Exception {
        final String truststoreType = "JKS";

        // Setup workers
        addRenewalWorker(WORKERID, WORKERNAME, truststoreType);
        addSigner(SIGNERID_6102, SIGNER_6102, SIGNER_6102_ENDENTITY, true);

        // Setup EJBCA end entity
        mockSetupEjbcaSearchResult();

        doRenewalFirstTime();
    }

    private void doRenewalFirstTimeUsingCLI() throws Exception {
        LOG.info(">doRenewalFirstTimeUsingCLI");
        
        CLITestHelper cli = new CLITestHelper(AdminCLI.class);
        
        int returnCode = cli.execute("renewsigner", SIGNER_6102, "-renewalworker", WORKERNAME, "-authcode", "foo123");
        byte[] outBytes = cli.getOut().toByteArray();
        byte[] errBytes = cli.getErr().toByteArray();
        LOG.info("outBytes: " + new String(outBytes));
        LOG.info("errBytes: " + new String(errBytes));
        assertEquals("renewsigner command", CommandLineInterface.RETURN_SUCCESS, returnCode);
        
        Properties response = new Properties();
        response.load(new ByteArrayInputStream(outBytes));
        
        // OK result
        assertEquals("Renewed successfully", new String(outBytes).trim());

        // Requested certificate
        assertTrue("should have requested certificate",
                mockEjbcaWs.isPkcs10RequestCalled());
        
        // Check that the right DN is included
        assertEquals("Requested DN", "CN=" + SIGNER_6102_ENDENTITY + ",C=SE", mockEjbcaWs.getLastPKCS10().getRequestDN());
        
        // Should have certificate and chain
        final X509Certificate cert = (X509Certificate) getWorkerSession()
                .getSignerCertificate(new WorkerIdentifier(SIGNERID_6102));
        assertNotNull(cert);
        final List<java.security.cert.Certificate> chain
                = getWorkerSession().getSignerCertificateChain(new WorkerIdentifier(SIGNERID_6102));
        assertNotNull(chain);
        assertTrue(chain.contains(cert));

        // Should not be any NEXTCERTSIGNKEY
        assertNull(getWorkerSession().getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("NEXTCERTSIGNKEY"));

        // Should be an DEFAULTKEY
        assertNotNull(getWorkerSession().getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("DEFAULTKEY"));
    }
    
    private void addWorkers() throws Exception {
        addRenewalWorker(WORKERID, WORKERNAME);
        addSigner(SIGNERID_6102, SIGNER_6102, SIGNER_6102_ENDENTITY);
    }

    private void removeSigners() throws Exception {
        removeWorker(WORKERID);
        removeWorker(6102);
    }

    protected void addRenewalWorker(final int signerId, final String signerName)
        throws Exception {
        addRenewalWorker(signerId, signerName, "PKCS12");
    }
    
    private void setupRenewalWorker(final int signerId, final String signerName) throws Exception {
        // Create keystore TODO: Don't create an empty one
        final String keystorePath = newTempFile().getAbsolutePath();
        final String keystorePassword = "foo123";
        createEmptyKeystore("PKCS12", keystorePath, keystorePassword);
    	
        getWorkerSession().setWorkerProperty(signerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
    	getWorkerSession().setWorkerProperty(signerId, WorkerConfig.IMPLEMENTATION_CLASS,
                "org.signserver.module.renewal.worker.RenewalWorker");
        getWorkerSession().setWorkerProperty(signerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS,
                "org.signserver.server.cryptotokens.P12CryptoToken");

        getWorkerSession().setWorkerProperty(signerId, "NAME", signerName);
        getWorkerSession().setWorkerProperty(signerId, "AUTHTYPE", "NOAUTH");
        getWorkerSession().setWorkerProperty(signerId, "KEYSTOREPATH", keystorePath);
        getWorkerSession().setWorkerProperty(signerId, "KEYSTOREPASSWORD", keystorePassword);
        getWorkerSession().setWorkerProperty(signerId, "DEFAULTKEY", "defaultKey");
    }

    protected void addRenewalWorker(final int signerId, final String signerName, 
            final String truststoreType) throws Exception {

        setupRenewalWorker(signerId, signerName);

        final String truststorePath = newTempFile().getAbsolutePath();
        final String truststorePassword = "foo123";
        createEmptyKeystore(truststoreType, truststorePath, truststorePassword);

        getWorkerSession().setWorkerProperty(signerId, "TRUSTSTOREPATH",
                truststorePath);
        getWorkerSession().setWorkerProperty(signerId, "TRUSTSTOREPASSWORD",
                truststorePassword);
        getWorkerSession().setWorkerProperty(signerId, "TRUSTSTORETYPE",
                truststoreType);
        getWorkerSession().setWorkerProperty(signerId, "EJBCAWSURL",
                EJBCAWSURL_PREFIX);
        getWorkerSession().setWorkerProperty(signerId, "DEFAULTKEY", "defaultKey");

        getWorkerSession().reloadConfiguration(signerId);
    }
    
    private void addRenewalWorkerMock(final GlobalConfigurationSessionMock conf, final MockWorkerSession workerSession, final int signerId, final String signerName)
        throws Exception {
        // Create keystore TODO: Don't create an empty one
        final String keystorePath = newTempFile().getAbsolutePath();
        final String keystorePassword = "foo123";
        createEmptyKeystore("PKCS12", keystorePath, keystorePassword);

        final String truststorePath = newTempFile().getAbsolutePath();
        final String truststorePassword = "foo123";
        createEmptyKeystore("PKCS12", truststorePath, truststorePassword);
        
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("NAME", "MockRenewalWorker");
        config.setProperty("AUTHTYPE", "NOAUTH");
        config.setProperty("SIGNINGCERTIFICATE", SIGN_CERT);
        config.setProperty("SIGNERCERTCHAIN", SIGN_CERT_CHAIN);
        config.setProperty("KEYDATA", KEY_DATA);
        config.setProperty("KEYSTOREPATH", keystorePath);
        config.setProperty("KEYSTOREPASSWORD", keystorePassword);
        config.setProperty("TRUSTSTOREPATH", truststorePath);
        config.setProperty("TRUSTSTOREPASSWORD", truststorePassword);
        config.setProperty("TRUSTSTORETYPE", "PKCS12");
        config.setProperty("EJBCAWSURL", EJBCAWSURL_PREFIX);
        config.setProperty("DEFAULTKEY", "defaultKey");
        
        final String CRYPTOTOKEN_CLASSNAME =
                "org.signserver.server.cryptotokens.KeystoreCryptoToken";
        
        workerSession.setupWorker(signerId, CRYPTOTOKEN_CLASSNAME, config, new RenewalWorker() {
            @Override
            protected WorkerSessionLocal getWorkerSession(IServices services) {
                return workerSession;
            }
        });
        
        workerSession.reloadConfiguration(signerId);
    }
    
    private void addSignerMock(final GlobalConfigurationSessionMock conf, final MockWorkerSession workerSession,
            final int signerId, final String signerName)
            throws IOException, KeyStoreException, NoSuchAlgorithmException,
                CertificateException, NoSuchProviderException {

        final WorkerConfig config = new WorkerConfig();
        config.setProperty("NAME", signerName);
        config.setProperty("AUTHTYPE", "NOAUTH");
        config.setProperty("SIGNINGCERTIFICATE", SIGN_CERT);
        config.setProperty("SIGNERCERTCHAIN", SIGN_CERT_CHAIN);
        config.setProperty("KEYDATA", KEY_DATA);
        config.setProperty("RENEWENDENTITY", "MockEndEntity");
        config.setProperty("KEYSPEC", DEFAULT_KEYSPEC);
        config.setProperty("KEYALG", DEFAULT_KEYALG);
        config.setProperty("SIGNATUREALGORITHM", "SHA1withRSA");
        config.setProperty("REQUESTDN", "CN=MockWorker");
        
        final String CRYPTOTOKEN_CLASSNAME =
                "org.signserver.server.cryptotokens.KeystoreCryptoToken";
        
        workerSession.setupWorker(signerId, CRYPTOTOKEN_CLASSNAME, config, new BaseSigner() {
            @Override
            public Response processData(Request signRequest,
                    RequestContext requestContext)
                    throws IllegalRequestException,
                    CryptoTokenOfflineException, SignServerException {
                return null;
            }
        });
        
        workerSession.reloadConfiguration(signerId);
    }
    
    private void addRenewalWorkerWithPEM(final int signerId, final String signerName)
    	throws Exception {
    	
    	setupRenewalWorker(signerId, signerName);
        
        final File truststorePath = new File(PathUtil.getAppHome(), "res" + File.separator + "test" + File.separator + "renewal.pem");
        getWorkerSession().setWorkerProperty(signerId, "TRUSTSTOREPATH", truststorePath.getAbsolutePath());
        getWorkerSession().setWorkerProperty(signerId, "TRUSTSTORETYPE", "PEM");
        getWorkerSession().setWorkerProperty(signerId, "EJBCAWSURL",
                EJBCAWSURL_PREFIX);

        getWorkerSession().reloadConfiguration(signerId);
    }
    
    private void addRenewalWorkerWithInlinePEM(final int signerId, final String signerName)
    	throws Exception {
    	
    	setupRenewalWorker(signerId, signerName);
        
        // TODO: Just any certificate for now as the test does not use HTTPS.
        // In the future replace with properer trust anchor
        final String trustChain = "-----BEGIN CERTIFICATE-----\n"
                + SIGN_CERT + "\n"
                + "-----END CERTIFICATE-----";
        
        getWorkerSession().setWorkerProperty(signerId, "TRUSTSTOREVALUE", trustChain);
        getWorkerSession().setWorkerProperty(signerId, "TRUSTSTORETYPE", "PEM");
        getWorkerSession().setWorkerProperty(signerId, "EJBCAWSURL",
                EJBCAWSURL_PREFIX);

        getWorkerSession().reloadConfiguration(signerId);
    }
    
    private void addRenewalWorkerWithInlineJKS(final int signerId, final String signerName)
    	throws Exception {
    	
    	setupRenewalWorker(signerId, signerName);
        
        // TODO: Just any certificate for now as the test does not use HTTPS.
        // In the future replace with properer trust anchor
        final String trustChain = "-----BEGIN CERTIFICATE-----\n"
                + SIGN_CERT + "\n"
                + "-----END CERTIFICATE-----";
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(null, null);
        final Collection certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(trustChain.getBytes(StandardCharsets.UTF_8)));
        int i = 0;
        for (Object o : certs) {
            if (o instanceof Certificate) {
                keystore.setCertificateEntry("cert-" + i, (Certificate) o);
                i++;
            }
        }
        final ByteArrayOutputStream bout = new ByteArrayOutputStream();
        keystore.store(bout, "foo123".toCharArray());
        final String value = new String(Base64.encode(bout.toByteArray()));
        
        getWorkerSession().setWorkerProperty(signerId, "TRUSTSTOREVALUE", value);
        getWorkerSession().setWorkerProperty(signerId, "TRUSTSTORETYPE", "JKS");
        getWorkerSession().setWorkerProperty(signerId, "TRUSTSTOREPASSWORD", "foo123");
        getWorkerSession().setWorkerProperty(signerId, "EJBCAWSURL",
                EJBCAWSURL_PREFIX);

        getWorkerSession().reloadConfiguration(signerId);
    }    
    
    
    private void mockSetupEjbcaSearchResult() {
        // Setup EJBCA end entity
        final UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername(SIGNER_6102_ENDENTITY);
        user1.setPassword("some-password-123");
        user1.setSubjectDN("CN=" + SIGNER_6102_ENDENTITY
                + ",O=SignServer Testing,C=SE");
        user1.setEndEntityProfileName("EMPTY");
        user1.setCertificateProfileName("ENDENTITY");
        user1.setCaName("SomeCA");
        final UserMatchEq match1 = new UserMatchEq();
        match1.setMatchwith(MockEjbcaWS.MATCH_WITH_USERNAME);
        match1.setMatchtype(MockEjbcaWS.MATCH_TYPE_EQUALS);
        match1.setMatchvalue(SIGNER_6102_ENDENTITY);
        final Map<UserMatchEq, List<UserDataVOWS>> findResult
                = new HashMap<>();
        findResult.put(match1, Arrays.asList(user1));
        mockEjbcaWs.setFindUserResults(findResult);
    }
    
    /**
     * Mockup worker session recording the explicitEccParameters parameter when
     * calling getCertificateRequest.
     * 
     * @author Marcus Lundblad
     *
     */
    private static class MockWorkerSession extends WorkerSessionMock {

        protected boolean explicitEccParametersSet = false;
        private WorkerConfig workerConfig;

        @Override
        public ICertReqData getCertificateRequest(WorkerIdentifier wi, ISignerCertReqInfo certReqInfo,
                boolean explicitEccParameters, boolean defaultKey)
                throws CryptoTokenOfflineException, InvalidWorkerIdException {
            explicitEccParametersSet = explicitEccParameters;
            
            return super.getCertificateRequest(wi, certReqInfo, explicitEccParameters, defaultKey);
        }

        @Override
        public int getWorkerId(String workerName) {
            // assume this is only called internally by RenewalWorker for this implementation...          
            return SIGNERID_6102;
        }

        @Override
        public void setupWorker(int workerId, String cryptoToken,
                WorkerConfig config, IProcessable worker) {
            // store last added worker config to allow returning it from the mock to the RenewalWorker
            workerConfig = config;
            super.setupWorker(workerId, cryptoToken, config, worker);
        }

        @Override
        public WorkerConfig getCurrentWorkerConfig(int signerId) {
            // always return latest added worker's config...
            return workerConfig;
        }
    }
}
