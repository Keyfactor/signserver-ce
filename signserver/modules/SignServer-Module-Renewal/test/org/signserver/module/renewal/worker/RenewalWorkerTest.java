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

import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.xml.namespace.QName;
import javax.xml.ws.Endpoint;
import org.apache.log4j.Logger;
import org.signserver.common.GenericPropertiesRequest;
import org.signserver.common.GenericPropertiesResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.RequestContext;
import org.signserver.module.renewal.common.RenewalWorkerProperties;
import org.signserver.module.renewal.ejbcaws.gen.EjbcaWS;
import org.signserver.module.renewal.ejbcaws.gen.EjbcaWSService;
import org.signserver.module.renewal.ejbcaws.gen.UserDataVOWS;

/**
 * Test case for the RenewalWorker.
 *
 * @author Markus Kilås
 * @version $Id$
 */
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
    public static final String DEFAULT_KEYALG = "RSA";
    public static final String DEFAULT_KEYSPEC = "2048";

    static final int MATCH_WITH_USERNAME = 0;
    static final int MATCH_TYPE_EQUALS = 0;

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(RenewalWorkerTest.class);

    private static final int WORKERID = 6101;

    private Endpoint ejbcaEndpoint;
    private MockEjbcaWS mockEjbcaWs;
    private EjbcaWS ejbcaws;

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
                = (GenericPropertiesResponse) getWorkerSession().process(
                    WORKERID, request, new RequestContext());

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
                .getSignerCertificate(SIGNERID_6102);
        assertNotNull(cert);
        final List<java.security.cert.Certificate> chain
                = getWorkerSession().getSignerCertificateChain(SIGNERID_6102);
        assertNotNull(chain);
        assertTrue(chain.contains(cert));

        // Should not be any NEXTCERTSIGNKEY
        assertNull(getWorkerSession().getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("NEXTCERTSIGNKEY"));

        // Should be an DEFAULTKEY
        assertNotNull(getWorkerSession().getCurrentWorkerConfig(SIGNERID_6102)
                .getProperty("DEFAULTKEY"));
    }

    /** 
     * Test Renewal without key generation (ie when NEXTCERTSIGNKEY exists)
     *
     * Config: NEXTCERTSIGNKEY
     * Request: -
     * Result: Only DEFAULTKEY (containing value from NEXTCERTSIGNKEY)
     */
    public void test03renewalExistingNextCertSignKey() throws Exception {
        // Setup workers
        addWorkers();

        // Setup EJBCA end entity
        mockSetupEjbcaSearchResult();

        // Generate a new key
        final String nextCertSignAlias = "test03_keyalias";
        getWorkerSession().generateSignerKey(SIGNERID_6102, DEFAULT_KEYALG,
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
                = (GenericPropertiesResponse) getWorkerSession().process(
                    WORKERID, request, new RequestContext());

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
                .getSignerCertificate(SIGNERID_6102);
        assertNotNull(cert);
        final List<java.security.cert.Certificate> chain
                = getWorkerSession().getSignerCertificateChain(SIGNERID_6102);
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
     */
    public void test04renewalExistingNextCertSignKeyForDefaultKey() throws Exception {
        // Setup workers
        addWorkers();

        // Setup EJBCA end entity
        mockSetupEjbcaSearchResult();

        // Generate a new key
        final String nextCertSignAlias = "test4_keyalias2";
        final String defaultKeyAlias = "test04_keyalias";
        getWorkerSession().generateSignerKey(SIGNERID_6102, DEFAULT_KEYALG,
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
                = (GenericPropertiesResponse) getWorkerSession().process(
                    WORKERID, request, new RequestContext());

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
                .getSignerCertificate(SIGNERID_6102);
        assertNotNull(cert);
        final List<java.security.cert.Certificate> chain
                = getWorkerSession().getSignerCertificateChain(SIGNERID_6102);
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
     */
    public void test05renewalExistingKeyForDefaultKey() throws Exception {
        // Setup workers
        addWorkers();

        // Setup EJBCA end entity
        mockSetupEjbcaSearchResult();

        // Generate a new key
        final String defaultKeyAlias = "test05_keyalias";
        getWorkerSession().generateSignerKey(SIGNERID_6102, DEFAULT_KEYALG,
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
                = (GenericPropertiesResponse) getWorkerSession().process(
                    WORKERID, request, new RequestContext());

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
                .getSignerCertificate(SIGNERID_6102);
        assertNotNull(cert);
        final List<java.security.cert.Certificate> chain
                = getWorkerSession().getSignerCertificateChain(SIGNERID_6102);
        assertNotNull(chain);
        assertTrue(chain.contains(cert));

        // DEFAULTKEY should not have changed
        assertEquals(defaultKeyAlias,  getWorkerSession()
                .getCurrentWorkerConfig(SIGNERID_6102).getProperty("DEFAULTKEY"));
    }

    /**
     * Test failure: No EJBCA end entity.
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
                = (GenericPropertiesResponse) getWorkerSession().process(
                    WORKERID, request, new RequestContext());

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
                = (GenericPropertiesResponse) getWorkerSession().process(
                    WORKERID, request, new RequestContext());

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
        addRenewalWorker(6101, "RenewalWorker_6101", truststoreType);
        addSigner(SIGNERID_6102, SIGNER_6102, SIGNER_6102_ENDENTITY);

        // Setup EJBCA end entity
        mockSetupEjbcaSearchResult();

        doRenewalFirstTime();
    }

    private void addWorkers() throws Exception {
        addRenewalWorker(6101, "RenewalWorker_6101");
        addSigner(SIGNERID_6102, SIGNER_6102, SIGNER_6102_ENDENTITY);
    }

    private void removeSigners() throws Exception {
        removeWorker(6101);
        removeWorker(6102);
    }

    protected void addRenewalWorker(final int signerId, final String signerName)
        throws Exception {
        addRenewalWorker(signerId, signerName, "PKCS12");
    }
    protected void addRenewalWorker(final int signerId, final String signerName, 
            final String truststoreType) throws Exception {

        // Create keystore TODO: Don't create an empty one
        final String keystorePath = newTempFile().getAbsolutePath();
        final String keystorePassword = "foo123";
        createEmptyKeystore("PKCS12", keystorePath, keystorePassword);

        final String truststorePath = newTempFile().getAbsolutePath();
        final String truststorePassword = "foo123";
        createEmptyKeystore(truststoreType, truststorePath, truststorePassword);

        getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL,
            "WORKER" + signerId + ".CLASSPATH",
            "org.signserver.module.renewal.worker.RenewalWorker");
        getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL,
            "WORKER" + signerId + ".SIGNERTOKEN.CLASSPATH",
            "org.signserver.server.cryptotokens.P12CryptoToken");

        getWorkerSession().setWorkerProperty(signerId, "NAME", signerName);
        getWorkerSession().setWorkerProperty(signerId, "AUTHTYPE", "NOAUTH");
        getWorkerSession().setWorkerProperty(signerId, "KEYSTOREPATH",
                keystorePath);
        getWorkerSession().setWorkerProperty(signerId, "KEYSTOREPASSWORD",
                keystorePassword);
        getWorkerSession().setWorkerProperty(signerId, "TRUSTSTOREPATH",
                truststorePath);
        getWorkerSession().setWorkerProperty(signerId, "TRUSTSTOREPASSWORD",
                truststorePassword);
        getWorkerSession().setWorkerProperty(signerId, "TRUSTSTORETYPE",
                truststoreType);
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
        match1.setMatchwith(MATCH_WITH_USERNAME);
        match1.setMatchtype(MATCH_TYPE_EQUALS);
        match1.setMatchvalue(SIGNER_6102_ENDENTITY);
        final Map<UserMatchEq, List<UserDataVOWS>> findResult
                = new HashMap<UserMatchEq, List<UserDataVOWS>>();
        findResult.put(match1, Arrays.asList(user1));
        mockEjbcaWs.setFindUserResults(findResult);
    }

}
