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
package org.signserver.testutils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;
import javax.naming.NamingException;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.ejbca.util.Base64;
import org.signserver.admin.cli.AdminCLI;
import org.signserver.client.cli.ClientCLI;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.RequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.statusrepo.IStatusRepositorySession;
import static org.junit.Assert.*;

/**
 * Base class for test cases.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ModulesTestCase extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ModulesTestCase.class);

    private static final int DUMMY1_SIGNER_ID = 5676;
    private static final String DUMMY1_SIGNER_NAME = "TestXMLSigner";
    
    private static final int CMSSIGNER1_ID = 5677;
    private static final String CMSSIGNER1_NAME = "TestCMSSigner";
    
    private static final int PDFSIGNER1_ID = 5678;
    private static final String PDFSIGNER1_NAME = "TestPDFSigner";
    
    private static final int TIMESTAMPSIGNER1_SIGNER_ID = 5879;
    private static final String TIMESTAMPSIGNER1_SIGNER_NAME = "TestTimeStampSigner";
    
    private static final int SODSIGNER1_SIGNER_ID = 5880;
    private static final String SODSIGNER1_SIGNER_NAME = "TestSODSigner";

    //Value created by calling org.signserver.server.cryptotokens.CryptoTokenUtils.CreateKeyDataForSoftCryptoToken using the dss10_signer1.p12
    private static final String KEYDATA1 = "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";
    // Value created by calling org.signserver.server.cryptotokens.CryptoTokenUtils.CreateSignerCertificateChainForSoftCryptoToken using the dss10_signer1.p12 and removing extra back-slashes
    private static final String CERTCHAIN1 = "MIIElTCCAn2gAwIBAgIIVFjQbKJpOTgwDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTEzMDUyNzEzNTIxNFoXDTE1MDUyNzEzNTIxNFowRzERMA8GA1UEAwwIU2lnbmVyIDExEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjzOexJZd1aFIsaNAtxEm8G4Hyh5ulTd/Ams5l/5hbpRckEzNMWJ4txBroJdaHa/qtfwfxuC8UerKU1nXHfvRJhdlzecJ+AWHJfH8nmgQc5wH5/gX1Afqb998cKKHovQw/KV6riR0B2zbTtWUa+hFfBakq/41XAcfZ6yKf+G/rlg6Nfao6+zvTPO5AGercWtIVO/oyRqkEn1xQqFID8RPtwqnHxFSP1JbRW0414iw+FW9fgM5BGfTdunKvKlm31TVug6i+HMfniLRfIg/g2hMp/KCz+72n69Y5fL8C0NgHmIIFtW0PTpvT0jG4Ta20wu+WcOdoZg1mNiCd+7hqJuqtwIDAQABo38wfTAdBgNVHQ4EFgQU+PykMUW8MnZhyCWzRRfvsuUUkegwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4ICAQBw+z9y2JEthx/sRfAY3CBXlcOkKMsXcHN+EtBicLZIbBySdijAFFizwCdbOAgOCOyjbXgHm2XWAVdP2kxBehc5/vChYUErWlDYaupCRsYMbwInmPBUwp1RuZ2LLwNMW1dVpWsQijRBhN8il5h13yVmWXWVpu7M6XDohnHLXFjcR3GhGv8j1GWzrEo1jC+1XnNcpMFsgh1eyFAhe6FDZeZa5g275VgOFoe072WQQ1kJ9bHE8/Eha0MoaQXvLS4pLPtNClWbVKRz+oi7esaMOSBbROFJmydpAqWngdiFswdwZm7qpAnSkP4EjCYCphZFtMC3bpnMIBe4LjaBLCuHlLSPoe6r3rbRO4jymOTpoip9WprVGzXaKDSdXvDl9KKVjghTumDgeQjSnT223F5cryLSMN1V1VYAkIZzsSc3n64cnmk+ilzk31KkBC/2f9PGWDTcZrApfzxj6ELwmMMfcBJcsLTaTaxcHfAvyKuXzMCsonLu9XoLPPFJoBT1iDfZyn3KzcQ4hDVL6eW+oT48fDYLCaQWD8XQaJzke0aulKwNctSDMSiBee/lXYROLjHXRaNSs7z2+JXnCO3OPPzu48m8kmPWt0n6lk04z935VcRMJifiiPBI98JMCFS+FnowjDw2XaVubh/OroIlTgxzMwMQJ3dqjhu82gR8RL/doEUPZg==;MIIFfzCCA2egAwIBAgIIMk1BOK8CwTwwDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzA4MTQyN1oXDTM2MDUyNzA4MTQyN1owTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgblgjTTkMp1QAhgWDprhvqE9zX1Ux/A/RTOu4G4f6CTkd6JEEkbdKZv+CKv4cRoVCtfO3wnOokFRw/1JMmHHiQ1Z//uDoDjo8jk8nek0ArFE9R5NT02wMJCQa/mP1wU9ZSl1tx3jQRUFB+rTNeCcPTft+1FL7UjYMdkRzl261IOlmXzDMA+EYIGJ2c2wYhOv2DqfQygNz5GOf0EFqlQZIt/pzopSS+0K8mNb53ROhg9GJujwzugSH5Z+r0fsVHbCV0QUkZBfkRo9KMcdaDEPa8xpYTjsFPqU6RcnGkVABhn8OS8SIWw2re1f+htj6p9EGbk1m0I9pWGBA9ktWnrqlqDXV+tEhhh1O4f+LHieoxiscrF7RXxlYqyam6oabfXsX3VAC0M1UkwIciE8wA1Sj/+dgoSMqvEDNDfwpEYt6l8Z8czDTWDi7MM2u5VY0nP3+A+PepKrOtrdaGSP396f4a7A3un1o6nQWHsyWQ7kc8GIn8zN5nykQaghGyYlHHYe1XUSPtHmxjbdsyztrkIis3cfjFne0XgPAiQuYx3T/B+po9BhGIUwCV0Qi/gWVN6NkydsbzMeRXELQYyK+lHgIGiEaBzQRRtXbnB+wQXi2IacJNdKqICwDsl/PvvcZI9ZV6pB/KIzB+8IJm0CLY24K0OXJs3Bqij8gmpvbI+o0wUCAwEAAaNjMGEwHQYDVR0OBBYEFCB6Id7orbsCqPtxWKQJYrnYWAWiMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUIHoh3uituwKo+3FYpAliudhYBaIwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQAxFvpOZF6Kol48cQeKWQ48VAe+h5dmyKMfDLDZX51IRzfKKsHLpFPxzGNw4t9Uv4YOR0CD9z81dR+c93t1lwwIpKbx9Qmq8jViHEHKYD9FXThM+cVpsT25pg35m3ONeUX/b++l2d+2QNNTWMvdsCtaQdybZqbYFIk0IjPwLLqdsA8Io60kuES4JnQahPdLkfm70rgAdmRDozOfSDaaWHY20DovkfvKUYjPR6MGAPD5w9dEb4wp/ZjATblyZnH+LTflwfftUAonmAw46E0Zgg143sO6RfOOnbwjXEc+KXd/KQ6kTQ560mlyRd6q7EIDYRfD4n4agKV2R5gvVPhMD0+IK7kagqKNfWa9z8Ue2N3MedyWnb9wv4wC69qFndGaIfYADkUykoOyLsVVteJ70PVJPXO7s66LucfD2R0wo2MpuOYCsTOm7HHS+uZ9VjHl2qQ0ZQG89Xn+AXnzPbk1INe2z0lq3hzCW5DTYBKsJEexErzMpLwiEqUYJUfR9EeCM8UPMtLSqz1utdPoIYhULGzt5lSJEpMHMbquYfWJxQiKCbvfxQsP5dLUMEIqTgjNdo98OlM7Z7zjYH9Kimz3wgAKSAIoQZr7Oy1dMHO5GK4jBtZ8wgsyyQ6DzQQ7R68XFVKarIW8SATeyubAP+WjdMwk/ZXzsDjMZEtENaBXzAefYA==";
    //Value created by calling org.signserver.server.cryptotokens.CryptoTokenUtils.CreateKeyDataForSoftCryptoToken using the dss10_tssigner1.p12
    private static final String CERTCHAIN2 = "MIIEkTCCAnmgAwIBAgIIeCvAS5OwAJswDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzEyMTU1NVoXDTIxMDUyNDEyMTU1NVowSjEUMBIGA1UEAwwLVFMgU2lnbmVyIDExEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnT38GG8i/bGnuFMwnOdg+caHMkdPBacRdBaIggwMPfE50SOZ2TLrDEHJotxYda7HS0+tX5dIcalmEYCls/ptHzO5TQpqdRTuTqxp5cMA379yhD0OqTVNAmHrvPj9IytktoAtB/xcjwkRTHagaCmg5SWNcLKyVUct7nbeRA5yDSJQsCAEGHNZbJ50vATg1DQEyKT87GKfSBsclA0WIIIHMt8/SRhpsUZxESayU6YA4KCxVtexF5x+COLB6CzzlRG9JA8WpX9yKgIMsMDAscsJLiLPjhET5hwAFm5ZRfQQG9LI06QNTGqukuTlDbYrQGAUR5ZXW00WNHfgS00CjUCu0QIDAQABo3gwdjAdBgNVHQ4EFgQUOF0FflO2G+IN6c92pCNlPoorGVwwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBADELkeIO9aiKjS/GaBUUhMr+k5UbVeK69WapU+7gTsWwa9D2vAOhAkfQ1OcUJoZaminv8pcNfo1Ey5qLtxBCmUy1fVomVWOPl6u1w8B6uYgE608hi2bfx28uIeksqpdqUX0Qf6ReUyl+FOh4xNrsyaF81TrIKt8ekq0iD+YAtT/jqgv4bUvs5fgIms4QOXgMUzNAP7cPU44KxcmR5I5Uy/Ag82hGIz64hZmeIDT0X59kbQvlZqFaiZvYOikoZSFvdM5kSVfItMgp7qmyLxuM/WaXqJWp6Mm+8ZZmcECugd4AEpE7xIiB7M/KEe+X4ItBNTKdAoaxWa+yeuYS7ol9rHt+Nogelj/06ZRQ0x03UqC7uKpgYAICjQEXIjcZofWSTh9KzKNfS1sQyIQ6yNTT2VMdYW9JC2OLKPV4AEJuBw30X8HOciJRRXOq9KRrIA2RSiaC5/3oAYscWuo31Fmj8CWQknXAIb39gPuZRwGOJbi1tUu2zmRsUNJfAe3hnvk+uxhnyp2vKB2KN5/VQgisx+8doEK/+Nbj/PPG/zASKimWG++5m0JNY4chIfR43gDDcF+4INof/8V84wbvUF+TpvP/mYM8wC9OkUyRvzqv9vjWOncCdbdjCuqPxDItwm9hhr+PbxsMaBes9rAiV9YT1FnpA++YpCufveFCQPDbCTgJ;MIIFfzCCA2egAwIBAgIIMk1BOK8CwTwwDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzA4MTQyN1oXDTM2MDUyNzA4MTQyN1owTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgblgjTTkMp1QAhgWDprhvqE9zX1Ux/A/RTOu4G4f6CTkd6JEEkbdKZv+CKv4cRoVCtfO3wnOokFRw/1JMmHHiQ1Z//uDoDjo8jk8nek0ArFE9R5NT02wMJCQa/mP1wU9ZSl1tx3jQRUFB+rTNeCcPTft+1FL7UjYMdkRzl261IOlmXzDMA+EYIGJ2c2wYhOv2DqfQygNz5GOf0EFqlQZIt/pzopSS+0K8mNb53ROhg9GJujwzugSH5Z+r0fsVHbCV0QUkZBfkRo9KMcdaDEPa8xpYTjsFPqU6RcnGkVABhn8OS8SIWw2re1f+htj6p9EGbk1m0I9pWGBA9ktWnrqlqDXV+tEhhh1O4f+LHieoxiscrF7RXxlYqyam6oabfXsX3VAC0M1UkwIciE8wA1Sj/+dgoSMqvEDNDfwpEYt6l8Z8czDTWDi7MM2u5VY0nP3+A+PepKrOtrdaGSP396f4a7A3un1o6nQWHsyWQ7kc8GIn8zN5nykQaghGyYlHHYe1XUSPtHmxjbdsyztrkIis3cfjFne0XgPAiQuYx3T/B+po9BhGIUwCV0Qi/gWVN6NkydsbzMeRXELQYyK+lHgIGiEaBzQRRtXbnB+wQXi2IacJNdKqICwDsl/PvvcZI9ZV6pB/KIzB+8IJm0CLY24K0OXJs3Bqij8gmpvbI+o0wUCAwEAAaNjMGEwHQYDVR0OBBYEFCB6Id7orbsCqPtxWKQJYrnYWAWiMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUIHoh3uituwKo+3FYpAliudhYBaIwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQAxFvpOZF6Kol48cQeKWQ48VAe+h5dmyKMfDLDZX51IRzfKKsHLpFPxzGNw4t9Uv4YOR0CD9z81dR+c93t1lwwIpKbx9Qmq8jViHEHKYD9FXThM+cVpsT25pg35m3ONeUX/b++l2d+2QNNTWMvdsCtaQdybZqbYFIk0IjPwLLqdsA8Io60kuES4JnQahPdLkfm70rgAdmRDozOfSDaaWHY20DovkfvKUYjPR6MGAPD5w9dEb4wp/ZjATblyZnH+LTflwfftUAonmAw46E0Zgg143sO6RfOOnbwjXEc+KXd/KQ6kTQ560mlyRd6q7EIDYRfD4n4agKV2R5gvVPhMD0+IK7kagqKNfWa9z8Ue2N3MedyWnb9wv4wC69qFndGaIfYADkUykoOyLsVVteJ70PVJPXO7s66LucfD2R0wo2MpuOYCsTOm7HHS+uZ9VjHl2qQ0ZQG89Xn+AXnzPbk1INe2z0lq3hzCW5DTYBKsJEexErzMpLwiEqUYJUfR9EeCM8UPMtLSqz1utdPoIYhULGzt5lSJEpMHMbquYfWJxQiKCbvfxQsP5dLUMEIqTgjNdo98OlM7Z7zjYH9Kimz3wgAKSAIoQZr7Oy1dMHO5GK4jBtZ8wgsyyQ6DzQQ7R68XFVKarIW8SATeyubAP+WjdMwk/ZXzsDjMZEtENaBXzAefYA==";
    //Value created by calling org.signserver.server.cryptotokens.CryptoTokenUtils.CreateKeyDataForSoftCryptoToken using the dss10_tssigner1.p12
    private static final String KEYDATA2 = "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";
    
    protected IWorkerSession workerSession;
    protected IGlobalConfigurationSession globalSession;
    protected IStatusRepositorySession statusSession;

    private static File signServerHome;

    private Properties config;
    
    private CLITestHelper adminCLI;
    private CLITestHelper clientCLI;
    private TestUtils testUtils = new TestUtils();
    private static Random random = new Random(1234);

    public ModulesTestCase() {
        try {
            workerSession = ServiceLocator.getInstance().lookupRemote(
                IWorkerSession.IRemote.class);
        } catch (NamingException ex) {
            fail("Could not lookup IWorkerSession: " + ex.getMessage());
        }
        try {
            globalSession = ServiceLocator.getInstance().lookupRemote(
                IGlobalConfigurationSession.IRemote.class);
        } catch (NamingException ex) {
            fail("Could not lookup IGlobalConfigurationSession: "
                    + ex.getMessage());
        }
        try {
            statusSession = ServiceLocator.getInstance().lookupRemote(
                IStatusRepositorySession.IRemote.class);
        } catch (NamingException ex) {
            fail("Could not lookup IStatusRepositorySession: "
                    + ex.getMessage());
        }
        final Properties defaultConfig = new Properties();
        InputStream in = null;
        try {
            defaultConfig.load(getClass().getResourceAsStream("/org/signserver/testutils/default-test-config.properties"));
            config = new Properties(defaultConfig);
            final File configFile = new File(getSignServerHome(),
                    "test-config.properties");
            if (configFile.exists()) {
                in = new FileInputStream(configFile);
                config.load(in);
            }
        } catch (Exception ex) {
            fail("Could not load test configuration: " + ex.getMessage());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOG.error("Could not close config file", ex);
                }
            }
        }
    }

    public CLITestHelper getAdminCLI() {
        if (adminCLI == null) {
            adminCLI = new CLITestHelper(AdminCLI.class);
        }
        return adminCLI;
    }

    public CLITestHelper getClientCLI() {
        if (clientCLI == null) {
            clientCLI = new CLITestHelper(ClientCLI.class);
        }
        return clientCLI;
    }
    
    

    protected IWorkerSession getWorkerSession() {
        return workerSession;
    }

    protected IGlobalConfigurationSession getGlobalSession() {
        return globalSession;
    }

    protected IStatusRepositorySession getStatusSession() {
        if (statusSession == null) {
            try {
               statusSession = ServiceLocator.getInstance().lookupRemote(
                    IStatusRepositorySession.IRemote.class);
            } catch (NamingException ex) {
                throw new RuntimeException("Could not lookup IStatusSession: " + ex.getMessage());
            }
        }
        return statusSession;
    }

    protected void addDummySigner1() throws CertificateException {
        addSoftDummySigner(getSignerIdDummy1(), getSignerNameDummy1());
    }

    protected int getSignerIdDummy1() {
        return DUMMY1_SIGNER_ID;
    }

    protected String getSignerNameDummy1() {
        return DUMMY1_SIGNER_NAME;
    }
    
    protected int getSignerIdTimeStampSigner1() {
        return TIMESTAMPSIGNER1_SIGNER_ID;
    }

    protected String getSignerNameTimeStampSigner1() {
        return TIMESTAMPSIGNER1_SIGNER_NAME;
    }
    
    protected int getSignerIdSODSigner1() {
        return SODSIGNER1_SIGNER_ID;
    }

    protected String getSignerNameSODSigner1() {
        return SODSIGNER1_SIGNER_NAME;
    }
    
    protected void addCMSSigner1() throws CertificateException {
        addSoftDummySigner("org.signserver.module.cmssigner.CMSSigner",
                getSignerIdCMSSigner1(), getSignerNameCMSSigner1(), KEYDATA1, CERTCHAIN1);
    }
    
    protected void addPDFSigner1() throws CertificateException {
    	addSoftDummySigner("org.signserver.module.pdfsigner.PDFSigner",
                getSignerIdPDFSigner1(), getSignerNamePDFSigner1(), KEYDATA1, CERTCHAIN1);
    }
    
    protected int getSignerIdCMSSigner1() {
        return CMSSIGNER1_ID;
    }
    
    protected String getSignerNameCMSSigner1() {
        return CMSSIGNER1_NAME;
    }
    
    protected int getSignerIdPDFSigner1() {
    	return PDFSIGNER1_ID;
    }
    
    protected String getSignerNamePDFSigner1() {
    	return PDFSIGNER1_NAME;
    }

    protected void addSigner(final String className) 
            throws CertificateException {
        addSoftDummySigner(className, DUMMY1_SIGNER_ID, DUMMY1_SIGNER_NAME,
                KEYDATA1, CERTCHAIN1);
    }

    /**
     * Load worker/global properties from file. This is not a complete 
     * implementation as the one used by the "setproperties" CLI command but 
     * enough to load the junittest-part-config.properties files used by the 
     * tests.
     * @param file The properties file to load
     * @throws IOException
     * @throws CertificateException in case a certificate could not be decoded 
     */
    protected void setProperties(final File file) throws IOException, CertificateException {
        InputStream in = null;
        try {
            in = new FileInputStream(file);
            Properties properties = new Properties();
            properties.load(in);
            setProperties(properties);
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }
    
    /**
     * Load worker/global properties from file. This is not a complete 
     * implementation as the one used by the "setproperties" CLI command but 
     * enough to load the junittest-part-config.properties files used by the 
     * tests.
     * @param in The inputstream to read properties from
     * @throws IOException
     * @throws CertificateException in case a certificate could not be decoded 
     */
    protected void setProperties(final InputStream in) throws IOException, CertificateException {
        try {
            Properties properties = new Properties();
            properties.load(in);
            setProperties(properties);
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }
    
    /**
     * Load worker/global properties. This is not a complete 
     * implementation as the one used by the "setproperties" CLI command but 
     * enough to load the junittest-part-config.properties files used by the 
     * tests.
     * @param file The properties file to load
     * @throws CertificateException in case a certificate could not be decoded
     */
    protected void setProperties(final Properties properties) throws CertificateException {
        for (Object o : properties.keySet()) {
            if (o instanceof String) {
                String key = (String) o;
                String value = properties.getProperty(key);
                if (key.startsWith("GLOB.")) {
                    key = key.substring("GLOB.".length());
                    globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, key, value);
                } else if (key.startsWith("WORKER") && key.contains(".") && key.indexOf(".") + 1 < key.length()) {
                    int id = Integer.parseInt(key.substring("WORKER".length(), key.indexOf(".")));
                    key = key.substring(key.indexOf(".") + 1);

                    if (key.startsWith("SIGNERCERTCHAIN")) {
                        String certs[] = value.split(";");
                        ArrayList<byte[]> chain = new ArrayList<byte[]>();
                        for (String base64cert : certs) {
                            byte[] cert = Base64.decode(base64cert.getBytes());
                            chain.add(cert);
                        }
                        workerSession.uploadSignerCertificateChain(id, chain, GlobalConfiguration.SCOPE_GLOBAL);
                    } else {
                        workerSession.setWorkerProperty(id, key, value);
                    }

                } else {
                    throw new RuntimeException("Unknown format for property: " + key);
                }
            }
        }
    }

    protected void addSoftDummySigner(final int signerId, final String signerName, final String keyData, final String certChain) throws CertificateException {
        addSoftDummySigner("org.signserver.module.xmlsigner.XMLSigner",
                signerId, signerName, keyData, certChain);
    }
    
    protected void addP12DummySigner(final int signerId, final String signerName, final File keystore, final String password) {
        addP12DummySigner("org.signserver.module.xmlsigner.XMLSigner",
                signerId, signerName, keystore, password);
    }
    
    protected void addSoftTimeStampSigner(final int signerId, final String signerName, final String keyData, final String certChain) throws CertificateException {
        addSoftDummySigner("org.signserver.module.tsa.TimeStampSigner",
                signerId, signerName, keyData, certChain);
    }
    
    protected void addSoftSODSigner(final int signerId, final String signerName, final String keyData, final String certChain) throws CertificateException {
        addSoftDummySigner("org.signserver.module.mrtdsodsigner.MRTDSODSigner",
                signerId, signerName, keyData, certChain);
    }

    protected void addSoftDummySigner(final String className, final int signerId, final String signerName, final String keyData, final String certChain) throws CertificateException {
        // Worker using SoftCryptoToken and RSA
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
            "WORKER" + signerId + ".CLASSPATH", className);
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
            "WORKER" + signerId + ".SIGNERTOKEN.CLASSPATH",
            "org.signserver.server.cryptotokens.SoftCryptoToken");
        workerSession.setWorkerProperty(signerId, "NAME", signerName);
        workerSession.setWorkerProperty(signerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(signerId, "KEYDATA", keyData);

        workerSession.uploadSignerCertificate(signerId, Base64.decode(certChain.getBytes()),GlobalConfiguration.SCOPE_GLOBAL);
        String certs[] = certChain.split(";");
        ArrayList<byte[]> chain = new ArrayList<byte[]>();
        for(String base64cert : certs){
            chain.add(Base64.decode(base64cert.getBytes()));
        }
        workerSession.uploadSignerCertificateChain(signerId, chain, GlobalConfiguration.SCOPE_GLOBAL);

        workerSession.reloadConfiguration(signerId);
        try {
            assertNotNull("Check signer available",
                    workerSession.getStatus(signerId));
        } catch (InvalidWorkerIdException ex) {
            fail("Worker was not added succefully: " + ex.getMessage());
        }
    }
    
    protected void addP12DummySigner(final String className, final int signerId, final String signerName, final File keystore, final String password) {
        addDummySigner(className, "org.signserver.server.cryptotokens.P12CryptoToken", signerId, signerName, keystore, password);
    }
    
    protected void addJKSDummySigner(final String className, final int signerId, final String signerName, final File keystore, final String password) {
        addDummySigner(className, "org.signserver.server.cryptotokens.JKSCryptoToken", signerId, signerName, keystore, password);
    }
    
    protected void addDummySigner(final String className, final String cryptoTokenClassName, final int signerId, final String signerName, final File keystore, final String password) {
        // Worker using SoftCryptoToken and RSA
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
            "WORKER" + signerId + ".CLASSPATH", className);
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
            "WORKER" + signerId + ".SIGNERTOKEN.CLASSPATH",
            cryptoTokenClassName);
        workerSession.setWorkerProperty(signerId, "NAME", signerName);
        workerSession.setWorkerProperty(signerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(signerId, "KEYSTOREPATH", keystore.getAbsolutePath());
        if (password != null) {
            workerSession.setWorkerProperty(signerId, "KEYSTOREPASSWORD", password);
        }

        workerSession.reloadConfiguration(signerId);
        try {
            assertNotNull("Check signer available",
                    workerSession.getStatus(signerId));
        } catch (InvalidWorkerIdException ex) {
            fail("Worker was not added succefully: " + ex.getMessage());
        }
    }

    protected void addSoftDummySigner(final int signerId, final String signerName) throws CertificateException {
        addSoftDummySigner(signerId, signerName, KEYDATA1, CERTCHAIN1);
    }
    
    protected void addSoftTimeStampSigner(final int signerId, final String signerName) throws CertificateException {
        addSoftTimeStampSigner(signerId, signerName, KEYDATA2, CERTCHAIN2);
    }
    
    protected void addSoftSODSigner(final int signerId, final String signerName) throws CertificateException {
        addSoftSODSigner(signerId, signerName, KEYDATA1, CERTCHAIN1);
    }

    private void removeGlobalProperties(int workerid) {
        final GlobalConfiguration gc = globalSession.getGlobalConfiguration();
        final Enumeration<String> en = gc.getKeyEnumeration();
        while (en.hasMoreElements()) {
            String key = en.nextElement();
            if (key.toUpperCase(Locale.ENGLISH)
                    .startsWith("GLOB.WORKER" + workerid)) {
                key = key.substring("GLOB.".length());
                globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, key);
            }
        }
    }

    protected void removeWorker(final int workerId) throws Exception {
        removeGlobalProperties(workerId);
        WorkerConfig wc = workerSession.getCurrentWorkerConfig(workerId);
        LOG.info("Got current config: " + wc.getProperties());
        final Iterator<Object> iter = wc.getProperties().keySet().iterator();
        while (iter.hasNext()) {
            final String key = (String) iter.next();
            workerSession.removeWorkerProperty(workerId, key);
        }
        workerSession.reloadConfiguration(workerId);  
        wc = workerSession.getCurrentWorkerConfig(workerId);
        LOG.info("Got current config after: " + wc.getProperties());
    }

    protected File getSignServerHome() throws Exception {
        if (signServerHome == null) {
            final String home = System.getenv("SIGNSERVER_HOME");
            assertNotNull("SIGNSERVER_HOME", home);
            signServerHome = new File(home);
            assertTrue("SIGNSERVER_HOME exists", signServerHome.exists());
        }
        return signServerHome;
    }

    protected Properties getConfig() {
        return config;
    }

    protected int getPublicHTTPPort() {
        return Integer.parseInt(config.getProperty("httpserver.pubhttp"));
    }

    protected int getPublicHTTPSPort() {
        return Integer.parseInt(config.getProperty("httpserver.pubhttps"));
    }

    protected int getPrivateHTTPSPort() {
        return Integer.parseInt(config.getProperty("httpserver.privhttps"));
    }

    /** Setup keystores for SSL. **/
    protected void setupSSLKeystores() {
        testUtils.setupSSLTruststore();
    }
    
    protected TestUtils getTestUtils() {
        return testUtils;
    }

    /**
     * Make a GenericSignRequest.
     */
    protected GenericSignResponse signGenericDocument(final int workerId, final byte[] data) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        final int requestId = random.nextInt();
        final GenericSignRequest request = new GenericSignRequest(requestId, data);
        final GenericSignResponse response = (GenericSignResponse) workerSession.process(workerId, request, new RequestContext());
        assertEquals("requestId", requestId, response.getRequestID());
        Certificate signercert = response.getSignerCertificate();
        assertNotNull(signercert);
        return response;
    }
}
