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
package org.signserver.module.renewal.service;

import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.xml.namespace.QName;
import javax.xml.ws.Endpoint;
import org.apache.log4j.Logger;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.GenericPropertiesRequest;
import org.signserver.common.GenericPropertiesResponse;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.module.renewal.common.RenewalWorkerProperties;
import org.signserver.module.renewal.ejbcaws.gen.EjbcaWS;
import org.signserver.module.renewal.ejbcaws.gen.EjbcaWSService;
import org.signserver.module.renewal.ejbcaws.gen.UserDataVOWS;
import org.signserver.module.renewal.worker.AbstractTestCase;
import org.signserver.module.renewal.worker.MockEjbcaWS;
import org.signserver.module.renewal.worker.UserMatchEq;
import static junit.framework.TestCase.assertNotNull;

/**
 * Test case for the RenewalService.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class RenewalServiceTest extends AbstractTestCase {
    
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
    private static final Logger LOG = Logger.getLogger(RenewalServiceTest.class);

    private static final int WORKERID = 6101;
    private static final String WORKERNAME = "RenewalWorker_6101";

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

    public void test30renewalServiceRun() throws Exception {
        try {
            addRenewalWorker(WORKERID, WORKERNAME);
            addCryptoWorker(CRYPTOWORKER_6200_ID, CRYPTOWORKER_6200, false);
            
            addSignerReferencingToken(SIGNERID_6102, SIGNER_6102, SIGNER_6102_ENDENTITY, CRYPTOWORKER_6200);
            getWorkerSession().setWorkerProperty(SIGNERID_6102, "RENEWWORKER", WORKERNAME);
            getWorkerSession().reloadConfiguration(RENEWALSERVICE_ID);

            addRenewalWorker(WORKERID, WORKERNAME);
            
            mockSetupEjbcaSearchResult();

            doRenewalFirstTime();
            
            final X509Certificate oldCert = (X509Certificate) getWorkerSession().getSignerCertificate(new WorkerIdentifier(SIGNERID_6102));
            final Date oldNotBefore = oldCert.getNotBefore();

            setupRenewalService(RENEWALSERVICE_ID, RENEWALSERVICE_NAME, SIGNER_6102);
            getWorkerSession().reloadConfiguration(RENEWALSERVICE_ID);

            // Wait for the service to have run
            Thread.sleep(30000);
           
            final X509Certificate newCert = (X509Certificate) getWorkerSession().getSignerCertificate(new WorkerIdentifier(SIGNERID_6102));
            final Date newNotBefore = newCert.getNotBefore();

            assertNotNull("new certificate", newCert);
            assertTrue("New notBefore: " + newNotBefore + ", Old: " + oldNotBefore, newNotBefore.after(oldNotBefore));
            assertFalse("New key", oldCert.getPublicKey().equals(newCert.getPublicKey()));
        } finally {
            // Disable the service so it won't run again while we try to remove it
            getWorkerSession().setWorkerProperty(RENEWALSERVICE_ID, "ACTIVE", "FALSE");
            getWorkerSession().reloadConfiguration(RENEWALSERVICE_ID);
            
            // Wait in case it is about to run
            try {
                Thread.sleep(30000);
            } catch (InterruptedException ex) {
                LOG.error("Interrupted", ex);
            }
            
            // Now remove the service when we are kind of sure it won't run while we are doing it
            removeWorker(RENEWALSERVICE_ID);
            
            removeWorker(CRYPTOWORKER_6200_ID);
        }    
    }
    
    public void test30renewalServiceRun_forDefaultKey() throws Exception {
        try {
            addRenewalWorker(WORKERID, WORKERNAME);
            addCryptoWorker(CRYPTOWORKER_6200_ID, CRYPTOWORKER_6200, false);
            
            addSignerReferencingToken(SIGNERID_6102, SIGNER_6102, SIGNER_6102_ENDENTITY, CRYPTOWORKER_6200);
            getWorkerSession().setWorkerProperty(SIGNERID_6102, "RENEWWORKER", WORKERNAME);
            getWorkerSession().setWorkerProperty(SIGNERID_6102, "RENEW_FORDEFAULTKEY", "true");
            getWorkerSession().reloadConfiguration(RENEWALSERVICE_ID);

            addRenewalWorker(WORKERID, WORKERNAME);
            
            mockSetupEjbcaSearchResult();

            doRenewalFirstTime();
            
            final X509Certificate oldCert = (X509Certificate) getWorkerSession().getSignerCertificate(new WorkerIdentifier(SIGNERID_6102));
            final Date oldNotBefore = oldCert.getNotBefore();

            setupRenewalService(RENEWALSERVICE_ID, RENEWALSERVICE_NAME, SIGNER_6102);
            getWorkerSession().reloadConfiguration(RENEWALSERVICE_ID);

            // Wait for the service to have run
            Thread.sleep(20000);

            final X509Certificate newCert = (X509Certificate) getWorkerSession().getSignerCertificate(new WorkerIdentifier(SIGNERID_6102));
            final Date newNotBefore = newCert.getNotBefore();

            assertNotNull("new certificate", newCert);
            assertTrue("New notBefore: " + newNotBefore + ", Old: " + oldNotBefore, newNotBefore.after(oldNotBefore));
            assertEquals("Same key", oldCert.getPublicKey(), newCert.getPublicKey());
            
            
        } finally {
            // Disable the service so it won't run again while we try to remove it
            getWorkerSession().setWorkerProperty(RENEWALSERVICE_ID, "ACTIVE", "FALSE");
            getWorkerSession().reloadConfiguration(RENEWALSERVICE_ID);
            
            // Wait in case it is about to run
            try {
                Thread.sleep(30000);
            } catch (InterruptedException ex) {
                LOG.error("Interrupted", ex);
            }
            
            // Now remove the service when we are kind of sure it won't run while we are doing it
            removeWorker(RENEWALSERVICE_ID);
            
            removeWorker(CRYPTOWORKER_6200_ID);
        }    
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
    
    private void setupRenewalService(final int signerId, final String signerName, final String workers) throws Exception {
        getWorkerSession().setWorkerProperty(signerId, WorkerConfig.TYPE, WorkerType.TIMED_SERVICE.name());
    	getWorkerSession().setWorkerProperty(signerId, WorkerConfig.IMPLEMENTATION_CLASS,
                "org.signserver.module.renewal.service.RenewalTimedService");
        getWorkerSession().setWorkerProperty(signerId, "NAME", signerName);
        getWorkerSession().setWorkerProperty(signerId, "AUTHTYPE", "NOAUTH");
        getWorkerSession().setWorkerProperty(signerId, "WORKERS", workers);
        getWorkerSession().setWorkerProperty(signerId, "INTERVAL", "10");
        getWorkerSession().setWorkerProperty(signerId, "ACTIVE", "true");
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

}
