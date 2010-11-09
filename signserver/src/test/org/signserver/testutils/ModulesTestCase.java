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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Locale;
import java.util.Properties;
import javax.naming.NamingException;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.ServiceLocator;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;

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
    private static final String DYMMY1_SIGNER_NAME = "TestXMLSigner";

    protected IWorkerSession workerSession;
    protected IGlobalConfigurationSession globalSession;

    private static File signServerHome;

    private Properties config;

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

    protected IWorkerSession getWorkerSession() {
        return workerSession;
    }

    protected IGlobalConfigurationSession getGlobalSession() {
        return globalSession;
    }


    protected void addDummySigner1() throws CertificateException {
        addSoftDummySigner(getSignerIdDummy1(), getSignerNameDummy1());
    }

    protected int getSignerIdDummy1() {
        return DUMMY1_SIGNER_ID;
    }

    protected String getSignerNameDummy1() {
        return DYMMY1_SIGNER_NAME;
    }

    protected void addSoftDummySigner(final int signerId, final String signerName, final String keyData, final String certChain) throws CertificateException {
        // Worker using SoftCryptoToken and RSA
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
            "WORKER" + signerId + ".CLASSPATH",
            "org.signserver.module.xmlsigner.XMLSigner");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
            "WORKER" + signerId + ".SIGNERTOKEN.CLASSPATH",
            "org.signserver.server.cryptotokens.SoftCryptoToken");
        workerSession.setWorkerProperty(signerId, "NAME", signerName);
        workerSession.setWorkerProperty(signerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(signerId, "KEYDATA", keyData);
//        workerSession.setWorkerProperty(signerId, "SIGNERCERTCHAIN", "MIICtjCCAZ6gAwIBAgIIEqzqEmAJ91AwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UEAwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0UwHhcNMDkwNTEzMTI1NDIzWhcNMTEwNTEzMTI1NDIzWjAhMRIwEAYDVQQDDAlwZGZzaWduZXIxCzAJBgNVBAYTAlNFMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvnWqZ/Nlv+ZrUhT8txG7vD2YdrI0vFUomEtqfBuSLrsmPXNhianzXA9XdPELaelz/Ga/czGQ94E873XScfPR22wFDjb3XYQN33Mm8lL4LAzrMKX9XHi0+Osdpw9hkHG9KYKNVkOl62i35YwiaDHV4vvEgOcJFKksPHd6l+9jK9QIDAQABo2AwXjAdBgNVHQ4EFgQUwFC0AY4l7vHyeGSr+RJAigXrVFcwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTMgpc8np+teLhm2bUcyCC5X1wJwDAOBgNVHQ8BAf8EBAMCBeAwDQYJKoZIhvcNAQEFBQADggEBAHFVyainF3Ris5K3qiVfULih5Cm7xsmHFRJf2qPZNsUcVscgvrJFcX/zuyLC4wjIuqqOVKcP3Wp2ufyC/4bV3bhjo2KEGRPvfeh9JAAGhj1E6DOUxZXtYRQcB2VLvRpdSSruVGvpsJpzunWvVgpZI3M7lhJldEfVxq9+81B3yOPMF6w6eIUx14jv1+FUvXvPK1n6Jvo7lo5MJ3J++dvVxI7u9ifeXfk3vFtgy4zLT9tONBEzfNR1CZPDsQx5GCtBjv1bwyI72wfA9HYiYYzeGVlmZSRy5tsd/u3FTO0UNvuXqCsYAA9Wai+NcxfwFCyoqi3Zlz4XYXN3ZWlhlmYS6PA=;MIIDUzCCAjugAwIBAgIIKvuaicGKsjUwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UEAwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0UwHhcNMDgxMTI0MTIwMDUwWhcNMTgxMTIyMTIwMDUwWjA3MREwDwYDVQQDDAhBZG1pbkNBMTEVMBMGA1UECgwMRUpCQ0EgU2FtcGxlMQswCQYDVQQGEwJTRTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIG+Lo4CGuFXfsJF0Py5k9zAWaPUtqBpBBZ+O7V8Mj0JoJgPxzkneohDp2B66+/sbw3/MTDJhmhBNG0kGViT1gzEAMiZ7KS1UqT1FTMNhkb+ODhEgvhzqWZnFoKf4t6lV4/lzZRMKT7OFY7gVBRQKR5LqX8YDDGZwMgQ/Xb0NsCDGPFenfmstWsJMaFghd4LC6iMfGtxvLblnqGJDDrU3is+0c/f70sBSVf4IBCaXQ3XFPouAh+dZqgFy1NYymBPh4eXr6OuG8tjO7NrRU1xIkC3QVDNyKp756rNxwh1uFxP3AWr2RQDFj14ree0CkKTnIeK4QwQdZunN4V1Zc5b0ScCAwEAAaNjMGEwHQYDVR0OBBYEFMyClzyen614uGbZtRzIILlfXAnAMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUzIKXPJ6frXi4Ztm1HMgguV9cCcAwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4IBAQApUHb6jiI6BGGUDj4/vxQVHq4pvcp2XnZpCgkk55a3+L3yQfnkog5CQ/XbMhLofmw1NR+snBURiMzUDmjH40ey96X/S5M+qYTE/6eQ/CDURBBeXvAR7JfdTMeuzh4nHNKn1EeN0axfOQCkPLl4swhogeh0PqL9LTlp5nhfVkasKeit41wuuOIJkOW4AA+ZG+O6LOHWhsI6YH80m4XkHeF8nQNkcTy+bE1fKpSBICZW5RxRT8uwjIxoAKN+w0J4Zlow9G9cZVcxDtB/H14OE2ZQXmDYd9UyFcFJzcicJ3qforXTWGHYo63gV+8OT8s5x7DuvosToPtn89JR1nb8E/sx");

        workerSession.uploadSignerCertificate(signerId, (X509Certificate)CertTools.getCertfromByteArray(Base64.decode(certChain.getBytes())),GlobalConfiguration.SCOPE_GLOBAL);
        String certs[] = certChain.split(";");
        ArrayList<Certificate> chain = new ArrayList<Certificate>();
        for(String base64cert : certs){
            X509Certificate cert = (X509Certificate)CertTools.getCertfromByteArray(Base64.decode(base64cert.getBytes()));
            chain.add(cert);
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

    protected void addSoftDummySigner(final int signerId, final String signerName) throws CertificateException {
        addSoftDummySigner(signerId, signerName, "AAAAojCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAr51qmfzZb/ma1IU/LcRu7w9mHayNLxVKJhLanwbki67Jj1zYYmp81wPV3TxC2npc/xmv3MxkPeBPO910nHz0dtsBQ42912EDd9zJvJS+CwM6zCl/Vx4tPjrHacPYZBxvSmCjVZDpetot+WMImgx1eL7xIDnCRSpLDx3epfvYyvUCAwEAAQAAAnowggJ2AgEAMA0GCSqGSIb3DQEBAQUABIICYDCCAlwCAQACgYEAr51qmfzZb/ma1IU/LcRu7w9mHayNLxVKJhLanwbki67Jj1zYYmp81wPV3TxC2npc/xmv3MxkPeBPO910nHz0dtsBQ42912EDd9zJvJS+CwM6zCl/Vx4tPjrHacPYZBxvSmCjVZDpetot+WMImgx1eL7xIDnCRSpLDx3epfvYyvUCAwEAAQKBgA8AJUDuBiy4Z29Lym/AXbFx4Ukbmhuxd9n0tlPrJM6BqZnjVmBhtDQxka0KHrPGy/bGXO1BUDaw2FPGwNU1HzR7dgf0iYu58ZJSzMPieSOb6qFhmdnG4cvgkfvsJkfdnQc4jJNXT1NtrJhCDveEcblbVz/Kck4gkPa0MvnuF7ppAkEA5/Wnue/l6l4h944rrWtW2lDHb1U3Lz3BGc4gT82cV6txe66yXiuNmiRIuKatvTED7dMkJGs/z/stS4eEitpr0wJBAMHQ02jourOXVGpCTYgQqjvV7dnvzQk0Uwo0zj+3jMfs4AwzqMhXjEFooUUrnVBmTlq9E1QT9B5Deg0qIDQYmRcCQQDGTqmXeDZq2RFXEG/c8kCtopPuZb8pHzWgdy3+q/z2orcBk4ggpEGKP20AmFc+wNHoGDP1As/qYoYF5ZT2FOhLAkA8N6+XpsdrSRdXNGZ2YgciNCOEVPc1ZuZuA14ZeePpsfUilWJZbKoNIH8KyLRF6KNrmddJhjGQvZJMSMxco0/dAkA3UxHfjCqkDSl0k7rbuhaJIBshlCXIpQCJfCnJnzVpJj/TR65hMSy1/0m6tDMjpVbRwkkHzbYlNKTrZ9bXxXAl",
                "MIICtjCCAZ6gAwIBAgIIEqzqEmAJ91AwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UEAwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0UwHhcNMDkwNTEzMTI1NDIzWhcNMTEwNTEzMTI1NDIzWjAhMRIwEAYDVQQDDAlwZGZzaWduZXIxCzAJBgNVBAYTAlNFMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvnWqZ/Nlv+ZrUhT8txG7vD2YdrI0vFUomEtqfBuSLrsmPXNhianzXA9XdPELaelz/Ga/czGQ94E873XScfPR22wFDjb3XYQN33Mm8lL4LAzrMKX9XHi0+Osdpw9hkHG9KYKNVkOl62i35YwiaDHV4vvEgOcJFKksPHd6l+9jK9QIDAQABo2AwXjAdBgNVHQ4EFgQUwFC0AY4l7vHyeGSr+RJAigXrVFcwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTMgpc8np+teLhm2bUcyCC5X1wJwDAOBgNVHQ8BAf8EBAMCBeAwDQYJKoZIhvcNAQEFBQADggEBAHFVyainF3Ris5K3qiVfULih5Cm7xsmHFRJf2qPZNsUcVscgvrJFcX/zuyLC4wjIuqqOVKcP3Wp2ufyC/4bV3bhjo2KEGRPvfeh9JAAGhj1E6DOUxZXtYRQcB2VLvRpdSSruVGvpsJpzunWvVgpZI3M7lhJldEfVxq9+81B3yOPMF6w6eIUx14jv1+FUvXvPK1n6Jvo7lo5MJ3J++dvVxI7u9ifeXfk3vFtgy4zLT9tONBEzfNR1CZPDsQx5GCtBjv1bwyI72wfA9HYiYYzeGVlmZSRy5tsd/u3FTO0UNvuXqCsYAA9Wai+NcxfwFCyoqi3Zlz4XYXN3ZWlhlmYS6PA=;MIIDUzCCAjugAwIBAgIIKvuaicGKsjUwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UEAwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0UwHhcNMDgxMTI0MTIwMDUwWhcNMTgxMTIyMTIwMDUwWjA3MREwDwYDVQQDDAhBZG1pbkNBMTEVMBMGA1UECgwMRUpCQ0EgU2FtcGxlMQswCQYDVQQGEwJTRTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIG+Lo4CGuFXfsJF0Py5k9zAWaPUtqBpBBZ+O7V8Mj0JoJgPxzkneohDp2B66+/sbw3/MTDJhmhBNG0kGViT1gzEAMiZ7KS1UqT1FTMNhkb+ODhEgvhzqWZnFoKf4t6lV4/lzZRMKT7OFY7gVBRQKR5LqX8YDDGZwMgQ/Xb0NsCDGPFenfmstWsJMaFghd4LC6iMfGtxvLblnqGJDDrU3is+0c/f70sBSVf4IBCaXQ3XFPouAh+dZqgFy1NYymBPh4eXr6OuG8tjO7NrRU1xIkC3QVDNyKp756rNxwh1uFxP3AWr2RQDFj14ree0CkKTnIeK4QwQdZunN4V1Zc5b0ScCAwEAAaNjMGEwHQYDVR0OBBYEFMyClzyen614uGbZtRzIILlfXAnAMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUzIKXPJ6frXi4Ztm1HMgguV9cCcAwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4IBAQApUHb6jiI6BGGUDj4/vxQVHq4pvcp2XnZpCgkk55a3+L3yQfnkog5CQ/XbMhLofmw1NR+snBURiMzUDmjH40ey96X/S5M+qYTE/6eQ/CDURBBeXvAR7JfdTMeuzh4nHNKn1EeN0axfOQCkPLl4swhogeh0PqL9LTlp5nhfVkasKeit41wuuOIJkOW4AA+ZG+O6LOHWhsI6YH80m4XkHeF8nQNkcTy+bE1fKpSBICZW5RxRT8uwjIxoAKN+w0J4Zlow9G9cZVcxDtB/H14OE2ZQXmDYd9UyFcFJzcicJ3qforXTWGHYo63gV+8OT8s5x7DuvosToPtn89JR1nb8E/sx");
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
        final WorkerConfig wc = workerSession.getCurrentWorkerConfig(workerId);
        final Iterator<Object> iter = wc.getProperties().keySet().iterator();
        while (iter.hasNext()) {
            final String key = (String) iter.next();
            workerSession.removeWorkerProperty(workerId, key);
        }
        workerSession.reloadConfiguration(workerId);
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
}
