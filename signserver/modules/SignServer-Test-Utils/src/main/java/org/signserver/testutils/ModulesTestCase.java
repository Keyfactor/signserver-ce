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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Properties;
import java.util.Random;
import java.util.HashMap;
import java.util.LinkedList;
import javax.naming.NamingException;
import javax.net.ssl.SSLSocketFactory;

import org.apache.log4j.Logger;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.admin.cli.AdminCLI;
import org.signserver.client.cli.ClientCLI;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionRemote;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.server.data.impl.ByteArrayReadableData;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.data.impl.FileReadableData;
import org.signserver.server.data.impl.TemporarlyWritableData;
import org.signserver.server.data.impl.UploadConfig;
import org.signserver.server.log.AdminInfo;
import org.signserver.statusrepo.StatusRepositorySessionRemote;
import org.signserver.test.conf.SignerConfigurationBuilder;
import org.signserver.test.conf.WorkerPropertiesBuilder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * Base class for test cases.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ModulesTestCase {

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

    private static final int VALIDATION_SERVICE_WORKER_ID = 5881;
    private static final String VALIDATION_SERVICE_WORKER_NAME = "TestValidationWorker";

    private static final int XML_VALIDATOR_WORKER_ID = 5882;
    private static final String XML_VALIDATOR_WORKER_NAME = "TestXMLValidator";

    protected static final String KEYSTORE_SIGNER00001_ALIAS = "signer00001";
    protected static final String KEYSTORE_SIGNER1_ALIAS = "signer00003";
    protected static final String KEYSTORE_TSSIGNER1_ALIAS = "ts00003";
    protected static final String KEYSTORE_AUTHCODESIGNER1_ALIAS = "code00003";
    protected static final String KEYSTORE_KEYSTORE_FILE = "res/test/dss10/dss10_keystore.p12";
    protected static final String KEYSTORE_CODE00002_ECDSA_ALIAS = "code00002";
    protected static final String KEYSTORE_APK00001_ALIAS = "apk00001";
    protected static final String KEYSTORE_APK00002_ECDSA_ALIAS = "apk00002";
    public static final String KEYSTORE_PASSWORD = "foo123";

    /**
     * SerialNumber: 32:4d:41:38:af:02:c1:3c
     * IssuerDN: CN=DSS Root CA 10, OU=Testing, O=SignServer, C=SE
     * Not Before: May 27 08:14:27 2011 GMT
     * Not After : May 27 08:14:27 2036 GMT
     *  SubjectDN: CN=DSS Root CA 10, OU=Testing, O=SignServer, C=SE
     */
   private static final String VALIDATOR_CERT_ISSUER =
        "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"
       + "dMwk/ZXzsDjMZEtENaBXzAefYA==";

   /**
    * Certificate for DemoRootCA2.
    *
    * <pre>
    * Serial Number: 26:02:00:71:07:af:7f:95
    *   Signature Algorithm: dsaWithSHA1
    *   Issuer: CN=DemoRootCA2, OU=EJBCA, O=SignServer Sample, C=SE
    *   Validity
    *       Not Before: Nov  9 16:09:48 2009 GMT
    *       Not After : Nov 10 16:09:48 2034 GMT
    *   Subject: CN=DemoRootCA2, OU=EJBCA, O=SignServer Sample, C=SE
    * </pre>
    */
   private static final String VALIDATOR_CERT_ISSUER4 =
       "MIIDPTCCAvygAwIBAgIIJgIAcQevf5UwCQYHKoZIzjgEAzBPMRQwEgYDVQQDDAtE"
       +"ZW1vUm9vdENBMjEOMAwGA1UECwwFRUpCQ0ExGjAYBgNVBAoMEVNpZ25TZXJ2ZXIg"
       +"U2FtcGxlMQswCQYDVQQGEwJTRTAeFw0wOTExMDkxNjA5NDhaFw0zNDExMTAxNjA5"
       +"NDhaME8xFDASBgNVBAMMC0RlbW9Sb290Q0EyMQ4wDAYDVQQLDAVFSkJDQTEaMBgG"
       +"A1UECgwRU2lnblNlcnZlciBTYW1wbGUxCzAJBgNVBAYTAlNFMIIBtzCCASsGByqG"
       +"SM44BAEwggEeAoGBAI+d9uiMBBzqdvlV3wSMdwRv/Qx2POGqh+m0M0tMYEwIGBdZ"
       +"Hm3+QSKIDTjcLRJgCGgTXSAJPCZtp43+kWCV5iGbbemBchOCh4Oe/4IPQERlfJhy"
       +"MH0gXLglG9KSbuKkqMSzaZoZk06q750KBKusKhK+mvhp08++KyXZna3p6itdAhUA"
       +"ntjYRJsYqqQtIt0htCGCEAHCkg8CgYA4E4VMplm16uizoUL+9erNtLI886f8pdO5"
       +"vXhcQG9IpZ0J7N6M4WQy8CFzTKjRJLs27TO2gDP8BE50mMOnbRvYmGIJsQ9lZHTj"
       +"UqltWh9PJ0VKF0fCwQbA3aY+v8PiHxELvami+YyBiYjE2C6b1ArKOw1QsEL0KakJ"
       +"cr22yWFaKgOBhQACgYEAiTsSMcEKhYCWg2ULDwD/4ueYyDcRvyoSrT7uCdGU0Y/w"
       +"2wPuI+kV5RfHxjs6YLDuJsQJg6rfi3RfgmwQJVzClDfgUN12qzRbSidepg/7ipkC"
       +"Gk0/eyY1A99z3K+FUZm2MVgune4ywCorPUpxz6WHS7/dSWYMWtSrr92PzgnwZbKj"
       +"YzBhMB0GA1UdDgQWBBRJ3xUuyl6ZroD3lFm3nw/AhCPeJTAPBgNVHRMBAf8EBTAD"
       +"AQH/MB8GA1UdIwQYMBaAFEnfFS7KXpmugPeUWbefD8CEI94lMA4GA1UdDwEB/wQE"
       +"AwIBhjAJBgcqhkjOOAQDAzAAMC0CFQCEGSmvJf6rxy6u7ZqY25qE7Hy21gIUPW4q"
       +"++YIS2fHyu+H4Pjgnodx5zI=";

    public static final String KEY_IMPL_CLASS = "IMPLEMENTATION_CLASS";
    public static final String KEY_CRYPTO_TOKEN_IMPL_CLASS = "CRYPTOTOKEN_IMPLEMENTATION_CLASS";
    public static final String KEY_KEYSTORE_PATH = "KEYSTOREPATH";
    public static final String KEY_KEYSTORE_PASSWORD = "KEYSTOREPASSWORD";
    public static final String KEY_NAME = "NAME";
    public static final String KEY_DEFAULT_KEY = "DEFAULTKEY";
    public static final String KEY_AUTH_TYPE = "AUTHTYPE";
    public static final String VALUE_NO_AUTH = "NOAUTH";
    public static final String WORKER_KEY_AUTH_TYPE = "AUTHTYPE";
    public static final String WORKER_KEY_USER_1 = "USER.USER1";
    public static final String WORKER_KEY_DISABLE_KEY_USAGE_COUNTER = "DISABLEKEYUSAGECOUNTER";
    public static final String WORKER_KEY_SLEEP_TIME = "SLEEP_TIME";
    public static final String WORKER_KEY_WORKER_LOGGER = "WORKERLOGGER";

    private WorkerSessionRemote workerSession;
    private static WorkerSessionRemote cWorkerSession;
    private ProcessSessionRemote processSession;
    private GlobalConfigurationSessionRemote globalSession;
    private static GlobalConfigurationSessionRemote cGlobalSession;
    private StatusRepositorySessionRemote statusSession;

    private static File signServerHome;

    private Properties config;
    private final Properties deployConfig = new Properties();

    private CLITestHelper adminCLI;
    private CLITestHelper clientCLI;
    private static CLITestHelper cClientCLI;
    private final TestUtils testUtils = new TestUtils();
    protected static Random random = new Random(1234);

    public ModulesTestCase() {
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
                setupSSLKeystores();
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

        // Load conf/signserver_deploy.properties (if it is available)
        try (FileInputStream fin = new FileInputStream(new File(getSignServerHome(), "conf/signserver_deploy.properties"))) {
            deployConfig.load(fin);
        } catch (FileNotFoundException ex) {
            // This file is not currently needed for running unit tests so lets just ignore it
            if (LOG.isDebugEnabled()) {
                LOG.debug("No conf/signsever_deploy.properties: " + ex.getMessage());
            }
        } catch (Exception ex) {
            fail("Could not load conf/signserver_deploy.properties: " + ex.getMessage());
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

    public static CLITestHelper getCurrentClientCLI() {
        if (cClientCLI == null) {
            cClientCLI = new CLITestHelper(ClientCLI.class);
        }
        return cClientCLI;
    }

    public WorkerSessionRemote getWorkerSession() {
        if (workerSession == null) {
            try {
                workerSession = ServiceLocator.getInstance().lookupRemote(WorkerSessionRemote.class);
            } catch (NamingException ex) {
                fail("Could not lookup WorkerSession: " + ex.getMessage());
            }
        }
        return workerSession;
    }

    public static WorkerSessionRemote getCurrentWorkerSession() {
        if(cWorkerSession == null) {
            try {
                cWorkerSession = ServiceLocator.getInstance().lookupRemote(WorkerSessionRemote.class);
            } catch (NamingException ex) {
                fail("Could not find WorkerSession: " + ex.getMessage());
            }
        }
        return cWorkerSession;
    }

    public ProcessSessionRemote getProcessSession() {
        if (processSession == null) {
            try {
                processSession = ServiceLocator.getInstance().lookupRemote(
                    ProcessSessionRemote.class);
            } catch (NamingException ex) {
                fail("Could not lookup WorkerSession: " + ex.getMessage());
            }
        }
        return processSession;
    }

    public static GlobalConfigurationSessionRemote getCurrentGlobalSession() {
        if (cGlobalSession == null) {
            try {
                cGlobalSession = ServiceLocator.getInstance().lookupRemote(GlobalConfigurationSessionRemote.class);
            } catch (NamingException ex) {
                fail("Could not lookup IGlobalConfigurationSession: " + ex.getMessage());
            }
        }
        return cGlobalSession;
    }

    public GlobalConfigurationSessionRemote getGlobalSession() {
        if (globalSession == null) {
            try {
                globalSession = ServiceLocator.getInstance().lookupRemote(
                        GlobalConfigurationSessionRemote.class);
            } catch (NamingException ex) {
                fail("Could not lookup IGlobalConfigurationSession: "
                        + ex.getMessage());
            }
        }
        return globalSession;
    }

    public StatusRepositorySessionRemote getStatusSession() {
        if (statusSession == null) {
            try {
                statusSession = ServiceLocator.getInstance().lookupRemote(
                StatusRepositorySessionRemote.class);
            } catch (NamingException ex) {
                fail("Could not lookup IStatusRepositorySession: "
                        + ex.getMessage());
            }
        }
        return statusSession;
    }

    public void addDummySigner1(boolean autoActivation) throws FileNotFoundException {
        addP12DummySigner(getSignerIdDummy1(), getSignerNameDummy1(), new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivation ? KEYSTORE_PASSWORD : null, KEYSTORE_SIGNER1_ALIAS);
    }

    public int getSignerIdDummy1() {
        return DUMMY1_SIGNER_ID;
    }

    public String getSignerNameDummy1() {
        return DUMMY1_SIGNER_NAME;
    }

    public int getSignerIdTimeStampSigner1() {
        return TIMESTAMPSIGNER1_SIGNER_ID;
    }

    public String getSignerNameTimeStampSigner1() {
        return TIMESTAMPSIGNER1_SIGNER_NAME;
    }

    public int getSignerIdSODSigner1() {
        return SODSIGNER1_SIGNER_ID;
    }

    public String getSignerNameSODSigner1() {
        return SODSIGNER1_SIGNER_NAME;
    }

    public void addCMSSigner1() throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.cmssigner.CMSSigner",
                getSignerIdCMSSigner1(), getSignerNameCMSSigner1(), new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), KEYSTORE_PASSWORD, KEYSTORE_SIGNER1_ALIAS);
    }

    public void addPDFSigner1() throws FileNotFoundException {
    	addP12DummySigner("org.signserver.module.pdfsigner.PDFSigner",
                getSignerIdPDFSigner1(), getSignerNamePDFSigner1(), new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), KEYSTORE_PASSWORD, KEYSTORE_SIGNER1_ALIAS);
    }

    public void addPDFSigner(final int workerId, final String workerName, final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.pdfsigner.PDFSigner",
                workerId, workerName, new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_SIGNER1_ALIAS);
    }

    public int getSignerIdCMSSigner1() {
        return CMSSIGNER1_ID;
    }

    public String getSignerNameCMSSigner1() {
        return CMSSIGNER1_NAME;
    }

    public int getSignerIdPDFSigner1() {
    	return PDFSIGNER1_ID;
    }

    public String getSignerNamePDFSigner1() {
    	return PDFSIGNER1_NAME;
    }

    public void addSigner(final String className, boolean autoActivate)
            throws FileNotFoundException {
        addSigner(className, DUMMY1_SIGNER_ID, DUMMY1_SIGNER_NAME, autoActivate);
    }

    public void addSigner(final String className) throws FileNotFoundException {
        addSigner(className, true);
    }

    public void addDummySigner(final int signerId, final String signerName, final boolean autoActivate) throws FileNotFoundException {
        addSigner("org.signserver.module.xmlsigner.XMLSigner", signerId, signerName, autoActivate);
    }

    /**
     * Adds a test XMLSigner using configuration of SignerConfigurationBuilder.
     * @param signerConfigurationBuilder A builder instance containing configuration for the Signer.
     * @throws FileNotFoundException If keystore file was not found at SIGNSERVER_HOME.
     */
    public static void addTestXMLSigner(
            final SignerConfigurationBuilder signerConfigurationBuilder
    ) throws FileNotFoundException {
        addTestSignerWithDefaultP12Keystore(
                signerConfigurationBuilder.withClassName("org.signserver.module.xmlsigner.XMLSigner")
        );
    }

    /**
     * Adds a test SleepWorker using configuration of SignerConfigurationBuilder.
     * @param signerConfigurationBuilder A builder instance containing configuration for the Worker.
     * @throws FileNotFoundException If keystore file was not found at SIGNSERVER_HOME.
     */
    public static void addTestSleepWorker(
            final SignerConfigurationBuilder signerConfigurationBuilder
    ) throws FileNotFoundException {
        addTestSignerWithDefaultP12Keystore(
                signerConfigurationBuilder.withClassName("org.signserver.server.signers.SleepWorker")
        );
    }

    public void addSigner(final String className,
            final int signerId, final String signerName, final boolean autoActivate)
        throws FileNotFoundException {
        addP12DummySigner(className, signerId, signerName,
                new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_SIGNER1_ALIAS);
    }

    /**
     * Adds a test Signer with default p12 keystore using configuration of SignerConfigurationBuilder. Defaults are:
     * <ul>
     *     <li>Crypto token class name: "org.signserver.server.cryptotokens.P12CryptoToken";</li>
     *     <li>Keystore file: SIGNSERVER_HOME / KEYSTORE_KEYSTORE_FILE = "res/test/dss10/dss10_keystore.p12";</li>
     *     <li>Keystore alias: KEYSTORE_SIGNER1_ALIAS = "signer00003".</li>
     * </ul>
     * @param signerConfigurationBuilder A builder instance containing configuration for the Signer.
     * @see #KEYSTORE_KEYSTORE_FILE
     * @see #KEYSTORE_SIGNER1_ALIAS
     * @throws FileNotFoundException If keystore file was not found at SIGNSERVER_HOME.
     */
    public static void addTestSignerWithDefaultP12Keystore(
            final SignerConfigurationBuilder signerConfigurationBuilder
    ) throws FileNotFoundException {
        addTestSigner(
                signerConfigurationBuilder
                        .withCryptoTokenClassName("org.signserver.server.cryptotokens.P12CryptoToken")
                        .withKeystore(new File(PathUtil.getAppHome(), KEYSTORE_KEYSTORE_FILE))
                        .withAlias(KEYSTORE_SIGNER1_ALIAS)
        );
    }

    public String getSigner1KeyAlias() {
        return KEYSTORE_SIGNER1_ALIAS;
    }

    /**
     * Load worker/global properties from file. This is not a complete
     * implementation as the one used by the "setproperties" CLI command but
     * enough to load the junittest-part-config.properties files used by the
     * tests.
     * @param file The properties file to load
     * @throws IOException IO Exception
     * @throws CertificateException in case a certificate could not be decoded
     */
    public void setProperties(final File file) throws IOException, CertificateException {
        try (InputStream in = new FileInputStream(file)) {
            Properties properties = new Properties();
            properties.load(in);
            setProperties(properties);
        }
    }

    /**
     * Load worker/global properties from file. This is not a complete
     * implementation as the one used by the "setproperties" CLI command but
     * enough to load the junittest-part-config.properties files used by the
     * tests.
     * @param in The inputstream to read properties from
     * @throws IOException IO Exception
     * @throws CertificateException in case a certificate could not be decoded
     */
    public void setProperties(final InputStream in) throws IOException, CertificateException {
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
     * @param properties The properties file to load
     * @throws CertificateException in case a certificate could not be decoded
     */
    public void setProperties(final Properties properties) throws CertificateException {
        for (Object o : properties.keySet()) {
            if (o instanceof String) {
                String key = (String) o;
                String value = properties.getProperty(key);
                if (key.startsWith("GLOB.")) {
                    key = key.substring("GLOB.".length());
                    getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, key, value);
                } else if (key.startsWith("WORKER") && key.contains(".") && key.indexOf(".") + 1 < key.length()) {
                    int id = Integer.parseInt(key.substring("WORKER".length(), key.indexOf(".")));
                    key = key.substring(key.indexOf(".") + 1);

                    if (key.startsWith("SIGNERCERTCHAIN")) {
                        String[] certs = value.split(";");
                        ArrayList<byte[]> chain = new ArrayList<>();
                        for (String base64cert : certs) {
                            byte[] cert = Base64.decode(base64cert.getBytes());
                            chain.add(cert);
                        }
                        getWorkerSession().uploadSignerCertificateChain(id, chain, GlobalConfiguration.SCOPE_GLOBAL);
                    } else {
                        getWorkerSession().setWorkerProperty(id, key, value);
                    }

                } else {
                    throw new RuntimeException("Unknown format for property: " + key);
                }
            }
        }
    }

    public void addP12DummySigner(
            final int signerId, final String signerName,
            final File keystore, final String password, final String alias
    ) {
        addP12DummySigner("org.signserver.module.xmlsigner.XMLSigner", signerId, signerName, keystore, password, alias);
    }

    public void addP12DummySigner(
            final String className,
            final int signerId, final String signerName,
            final File keystore, final String password, final String alias
    ) {
        addDummySigner(
                className, "org.signserver.server.cryptotokens.P12CryptoToken",
                signerId, signerName, keystore, password, alias
        );
    }

    public void addJKSDummySigner(final String className, final int signerId, final String signerName, final File keystore, final String password, final String alias) {
        addDummySigner(className, "org.signserver.server.cryptotokens.JKSCryptoToken", signerId, signerName, keystore, password, alias);
    }

    public void addDummySigner(
            final String className, final String cryptoTokenClassName,
            final int signerId, final String signerName,
            final File keystore, final String password, final String alias
    ) {
        HashMap<String, String> properties = new HashMap<>();
        properties.put(WorkerConfig.TYPE,WorkerType.PROCESSABLE.name());
        properties.put(KEY_IMPL_CLASS,className);
        if (cryptoTokenClassName != null) {
            properties.put(KEY_CRYPTO_TOKEN_IMPL_CLASS,cryptoTokenClassName);
        }
        properties.put(KEY_NAME,signerName);
        properties.put(KEY_AUTH_TYPE,VALUE_NO_AUTH);
        if (keystore != null) {
            properties.put(KEY_KEYSTORE_PATH,keystore.getAbsolutePath());
        }
        if (alias != null) {
            properties.put(KEY_DEFAULT_KEY,alias);
        }
        if (password != null) {
            properties.put(KEY_KEYSTORE_PASSWORD,password);
        }
        getWorkerSession().updateWorkerProperties(signerId,properties,new LinkedList<>());

        getWorkerSession().reloadConfiguration(signerId);
        try {
            assertNotNull("Check signer available",
                    getWorkerSession().getStatus(new WorkerIdentifier(signerId)));
        } catch (InvalidWorkerIdException ex) {
            fail("Worker was not added successfully: " + ex.getMessage());
        }
    }

    /**
     * Adds a test signer using configuration of SignerConfigurationBuilder.
     * @param signerConf A builder instance containing configuration for the Signer.
     */
    public static void addTestSigner(final SignerConfigurationBuilder signerConf) {
        final int signerId = signerConf.getSignerId();
        final WorkerSessionRemote workerSession = getCurrentWorkerSession();
        // Set properties if any
        workerSession.setWorkerProperty(signerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(signerId, KEY_IMPL_CLASS, signerConf.getClassName());
        //
        if (signerConf.getCryptoTokenClassName() != null) {
            workerSession.setWorkerProperty(signerId, KEY_CRYPTO_TOKEN_IMPL_CLASS, signerConf.getCryptoTokenClassName());
        }
        workerSession.setWorkerProperty(signerId, KEY_NAME, signerConf.getSignerName());
        workerSession.setWorkerProperty(signerId, KEY_AUTH_TYPE, VALUE_NO_AUTH);
        if (signerConf.getKeystore() != null) {
            workerSession.setWorkerProperty(signerId, KEY_KEYSTORE_PATH, signerConf.getKeystore().getAbsolutePath());
        }
        if (signerConf.getAlias() != null) {
            workerSession.setWorkerProperty(signerId, KEY_DEFAULT_KEY, signerConf.getAlias());
        }
        if(signerConf.isAutoActivate()) {
            workerSession.setWorkerProperty(signerId, KEY_KEYSTORE_PASSWORD, KEYSTORE_PASSWORD);
        }
        if (signerConf.getKeystorePassword() != null) {
            workerSession.setWorkerProperty(signerId, KEY_KEYSTORE_PASSWORD, signerConf.getKeystorePassword());
        }
        // Reload
        workerSession.reloadConfiguration(signerId);
        try {
            assertNotNull("Check signer available", workerSession.getStatus(new WorkerIdentifier(signerId)));
        } catch (InvalidWorkerIdException ex) {
            fail("Worker was not added successfully: " + ex.getMessage());
        }
    }

    public void addTimeStampSigner(final int signerId, final String signerName,
                                   final String alias, final boolean autoActivate)
            throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.tsa.TimeStampSigner", signerId, signerName, new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivate ? KEYSTORE_PASSWORD : null, alias);
        getWorkerSession().setWorkerProperty(signerId, "DEFAULTTSAPOLICYOID", "1.2.3");
        getWorkerSession().setWorkerProperty(signerId, "ACCEPTANYPOLICY", "true");
        getWorkerSession().reloadConfiguration(signerId);
    }

    public void addTimeStampSigner(final int signerId, final String signerName, final boolean autoActivate) throws FileNotFoundException {
        addTimeStampSigner(signerId, signerName, KEYSTORE_TSSIGNER1_ALIAS, autoActivate);
    }

    public void addMSTimeStampSigner(final int signerId, final String signerName, final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.tsa.MSAuthCodeTimeStampSigner", signerId, signerName, new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_TSSIGNER1_ALIAS);
    }

    public void addMSAuthCodeSigner(final int signerId, final String signerName, final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.msauthcode.signer.MSAuthCodeSigner", signerId, signerName, new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_AUTHCODESIGNER1_ALIAS);
    }

    public void addMSAuthCodeCMSSigner(final int signerId, final String signerName, final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.msauthcode.signer.MSAuthCodeCMSSigner", signerId, signerName, new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_AUTHCODESIGNER1_ALIAS);
    }

    public void addAppxSigner(final int signerId, final String signerName, final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.msauthcode.signer.AppxSigner", signerId, signerName, new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_AUTHCODESIGNER1_ALIAS);
    }

    public void addAppxCMSSigner(final int signerId, final String signerName, final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.msauthcode.signer.AppxCMSSigner", signerId, signerName, new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_AUTHCODESIGNER1_ALIAS);
    }

    public void addJArchiveSigner(final int signerId, final String signerName, final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.jarchive.signer.JArchiveSigner", signerId, signerName, new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_AUTHCODESIGNER1_ALIAS);
    }

    public void addJArchiveSignerECDSA(final int signerId, final String signerName, final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.jarchive.signer.JArchiveSigner", signerId, signerName, new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_CODE00002_ECDSA_ALIAS);
    }

    public void addJArchiveCMSSigner(final int signerId, final String signerName, final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.jarchive.signer.JArchiveCMSSigner", signerId, signerName, new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_AUTHCODESIGNER1_ALIAS);
    }

    public void addJArchiveCMSSignerECDSA(final int signerId, final String signerName, final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.jarchive.signer.JArchiveCMSSigner", signerId, signerName, new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_CODE00002_ECDSA_ALIAS);
    }

    public void addApkSigner(final int signerId, final String signerName, final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.apk.signer.ApkSigner", signerId, signerName, new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_APK00001_ALIAS);
    }

    public void addApkSignerECDSA(final int signerId, final String signerName, final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.apk.signer.ApkSigner", signerId, signerName, new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_APK00002_ECDSA_ALIAS);
    }

    public void addApkRotateSigner(final int signerId, final String signerName, final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.apk.signer.ApkRotateSigner", signerId, signerName, new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_APK00001_ALIAS);
    }

    public void addApkLineageSigner(final int signerId, final String signerName, final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.apk.signer.ApkLineageSigner", signerId, signerName, new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_APK00001_ALIAS);
    }

    public void addApkHashSigner(final int signerId, final String signerName, final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.apk.signer.ApkHashSigner", signerId, signerName, new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE), autoActivate ? KEYSTORE_PASSWORD : null, KEYSTORE_APK00001_ALIAS);
    }


    public void addExtendedCMSSigner(final int signerId, final String signerName,
                                     final boolean autoActivate)
            throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.extendedcmssigner.ExtendedCMSSigner",
                          signerId, signerName,
                          new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE),
                                   autoActivate ? KEYSTORE_PASSWORD : null,
                                   KEYSTORE_SIGNER1_ALIAS);
    }

    public void addZoneZipFileServerSideSigner(final int signerId, final String signerName,
            final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.dnssec.signer.ZoneZipFileServerSideSigner",
                signerId, signerName,
                new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE),
                autoActivate ? KEYSTORE_PASSWORD : null,
                KEYSTORE_SIGNER1_ALIAS);
    }

    public void addZoneFileServerSideSigner(final int signerId, final String signerName,
            final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner("org.signserver.module.dnssec.signer.ZoneFileServerSideSigner",
                signerId, signerName,
                new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE),
                autoActivate ? KEYSTORE_PASSWORD : null,
                KEYSTORE_SIGNER1_ALIAS);
    }

    public void addSignerWithDummyKeystore(final String implementationClass, final int signerId, final String signerName,
            final boolean autoActivate) throws FileNotFoundException {
        addP12DummySigner(implementationClass,
                signerId, signerName,
                new File(getSignServerHome(), KEYSTORE_KEYSTORE_FILE),
                autoActivate ? KEYSTORE_PASSWORD : null,
                KEYSTORE_SIGNER1_ALIAS);
    }


    public void addXMLValidator() throws Exception {
        // VALIDATION SERVICE
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.validationservice.server.ValidationServiceWorker");
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, "org.signserver.server.cryptotokens.KeystoreCryptoToken");
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID,
                KEY_KEYSTORE_PATH,
                getSignServerHome() + File.separator + "res" + File.separator +
                        "test" + File.separator + "dss10" + File.separator +
                        "dss10_signer1.p12");
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID,
                "KEYSTORETYPE", "PKCS12");
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID,
                KEY_KEYSTORE_PASSWORD, "foo123");
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID,
                KEY_DEFAULT_KEY, "Signer 1");
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID, KEY_AUTH_TYPE, VALUE_NO_AUTH);
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID, KEY_NAME, VALIDATION_SERVICE_WORKER_NAME);
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID, "VAL1.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID, "VAL1.ISSUER1.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\n" + VALIDATOR_CERT_ISSUER + "\n-----END CERTIFICATE-----\n");
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID, "VAL1.ISSUER2.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\n" + VALIDATOR_CERT_ISSUER4 + "\n-----END CERTIFICATE-----\n");
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID, "VAL1.TESTPROP", "TEST");
        getWorkerSession().setWorkerProperty(VALIDATION_SERVICE_WORKER_ID, "VAL1.REVOKED", "");
        getWorkerSession().reloadConfiguration(VALIDATION_SERVICE_WORKER_ID);

        // XMLVALIDATOR
        getWorkerSession().setWorkerProperty(XML_VALIDATOR_WORKER_ID, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        getWorkerSession().setWorkerProperty(XML_VALIDATOR_WORKER_ID, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.xmlvalidator.XMLValidator");
        getWorkerSession().setWorkerProperty(XML_VALIDATOR_WORKER_ID, KEY_NAME, XML_VALIDATOR_WORKER_NAME);
        getWorkerSession().setWorkerProperty(XML_VALIDATOR_WORKER_ID, KEY_AUTH_TYPE, VALUE_NO_AUTH);
        getWorkerSession().setWorkerProperty(XML_VALIDATOR_WORKER_ID, "VALIDATIONSERVICEWORKER", VALIDATION_SERVICE_WORKER_NAME);
        getWorkerSession().reloadConfiguration(XML_VALIDATOR_WORKER_ID);
    }

    public int getWorkerIdXmlValidator() {
        return XML_VALIDATOR_WORKER_ID;
    }

    public String getWorkerNameXmlValidator() {
        return XML_VALIDATOR_WORKER_NAME;
    }

    public int getWorkerIdValidationService() {
        return VALIDATION_SERVICE_WORKER_ID;
    }

    private void removeGlobalProperties(int workerid) {
        final GlobalConfiguration gc = getGlobalSession().getGlobalConfiguration();
        final Enumeration<String> en = gc.getKeyEnumeration();
        while (en.hasMoreElements()) {
            String key = en.nextElement();
            if (key.toUpperCase(Locale.ENGLISH)
                    .startsWith("GLOB.WORKER" + workerid)) {
                key = key.substring("GLOB.".length());
                getGlobalSession().removeProperty(GlobalConfiguration.SCOPE_GLOBAL, key);
            }
        }
    }

    public void removeWorker(final int workerId) {
        removeGlobalProperties(workerId);
        WorkerConfig wc = getWorkerSession().getCurrentWorkerConfig(workerId);
        LOG.info("Got current config: " + wc.getProperties());
        for (Object o : wc.getProperties().keySet()) {
            final String key = (String) o;
            getWorkerSession().removeWorkerProperty(workerId, key);
        }
        getWorkerSession().reloadConfiguration(workerId);
        wc = getWorkerSession().getCurrentWorkerConfig(workerId);
        LOG.info("Got current config after: " + wc.getProperties());
    }

    public File getSignServerHome() throws FileNotFoundException {
        if (signServerHome == null) {
            signServerHome = PathUtil.getAppHome();
        }
        return signServerHome;
    }

    public Properties getConfig() {
        return config;
    }

    public Properties getDeployConfig() {
        return deployConfig;
    }

    public int getPublicHTTPPort() {
        return Integer.parseInt(config.getProperty("httpserver.pubhttp"));
    }

    public int getPublicHTTPSPort() {
        return Integer.parseInt(config.getProperty("httpserver.pubhttps"));
    }

    public int getPrivateHTTPSPort() {
        return Integer.parseInt(config.getProperty("httpserver.privhttps"));
    }

    public String getHTTPHost() {
        return config.getProperty("httpserver.hostname", "localhost");
    }

    public String getPreferredHTTPProtocol() {
        return config.getProperty("httpserver.prefproto", "http://");
    }

    public int getPreferredHTTPPort() {
        return Integer.parseInt(config.getProperty("httpserver.prefport", config.getProperty("httpserver.pubhttp")));
    }

    /** @return IP used by JUnit tests to access SignServer through the HTTPHost. */
    public String getClientIP() {
        return config.getProperty("httpclient.ipaddress", "127.0.0.1");
    }

    /**
     * Setup keystore for SSL.
     * @deprecated Use static method initSSLKeystore() instead.
     **/
    public SSLSocketFactory setupSSLKeystores() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, KeyManagementException, UnrecoverableKeyException {
        return testUtils.setupSSLTruststore();
    }

    /**
     * Initializes the SSLSocketFactory containing the default truststore.jks for testing.
     * @return SSLSocketFactory.
     * @throws KeyStoreException KeyStore Exception.
     * @throws IOException IO exception.
     * @throws NoSuchAlgorithmException In case of invalid algorithm.
     * @throws CertificateException Certificate exception.
     * @throws KeyManagementException In case of key exception.
     * @throws UnrecoverableKeyException In case of key exception.
     */
    public static SSLSocketFactory initSSLKeystore()
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
            KeyManagementException, UnrecoverableKeyException
    {
        return TestUtils.initSSLTruststore();
    }

    public TestUtils getTestUtils() {
        return testUtils;
    }

    /**
     * Make a GenericSignRequest.
     */
    public GenericSignResponse signGenericDocument(final int workerId, final byte[] data) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        return signGenericDocument(workerId, data, new RemoteRequestContext());
    }

    /**
     * Make a GenericSignRequest.
     */
    public GenericSignResponse signGenericDocument(final int workerId, final byte[] data, final RemoteRequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        final int requestId = random.nextInt();
        final GenericSignRequest request = new GenericSignRequest(requestId, data);
        final GenericSignResponse response = (GenericSignResponse) getProcessSession().process(new WorkerIdentifier(workerId), request, requestContext);
        assertEquals("requestId", requestId, response.getRequestID());
        Certificate signercert = response.getSignerCertificate();
        assertNotNull(signercert);
        return response;
    }

    public PublicKey getPublicKeyFromRequest(final PKCS10CertificationRequest req)
            throws InvalidKeyException, NoSuchAlgorithmException {
        final JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest =
                new JcaPKCS10CertificationRequest(req);
        return jcaPKCS10CertificationRequest.getPublicKey();
    }

    public static CloseableReadableData createRequestData(byte[] data) {
        return new ByteArrayReadableData(data, new UploadConfig().getRepository());
    }

    public static CloseableReadableData createRequestData(Properties properties) throws IOException {
        try (ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
            properties.store(bout, null);
            return new ByteArrayReadableData(bout.toByteArray(), new UploadConfig().getRepository());
        }
    }

    public static CloseableReadableData createRequestDataKeepingFile(File file) {
        return new FileReadableData(file);
    }

    public static CloseableWritableData createResponseData(final boolean defaultToDisk) {
        return new TemporarlyWritableData(defaultToDisk, new UploadConfig().getRepository());
    }

    public static AdminInfo createAdminInfo() {
        return new AdminInfo("CN=Unit Tester", "CN=Testing CA", new BigInteger("4242"));
    }

    public static double getJavaVersion() {
        String version = System.getProperty("java.version");
        int pos = version.indexOf('.');
        pos = version.indexOf('.', pos + 1);
        return Double.parseDouble(version.substring(0, pos));
    }

    /**
     * Is OS running this test-Windows?.
     */
    public static boolean isWindows() {
        String OS = System.getProperty("os.name").toLowerCase(Locale.ENGLISH);
        return (OS.contains("win"));
    }

    /**
     * Updates properties of the worker using properties of WorkerPropertiesBuilder.
     * @param workerProps A builder instance containing properties for the Worker.
     */
    public static void applyWorkerPropertiesAndReload(final WorkerPropertiesBuilder workerProps) {
        final int workerId = workerProps.getWorkerId();
        final WorkerSessionRemote workerSession = getCurrentWorkerSession();
        // Apply properties if any
        if(workerProps.getAuthType() != null) {
            workerSession.setWorkerProperty(workerId, WORKER_KEY_AUTH_TYPE, workerProps.getAuthType());
        }
        if(workerProps.getUser1() != null) {
            workerSession.setWorkerProperty(workerId, WORKER_KEY_USER_1, workerProps.getUser1());
        }
        if(workerProps.isDisableKeyUsageCounter()) {
            workerSession.setWorkerProperty(workerId, WORKER_KEY_DISABLE_KEY_USAGE_COUNTER, "TRUE");
        }
        if(workerProps.getSleepTime() != null) {
            workerSession.setWorkerProperty(workerId, WORKER_KEY_SLEEP_TIME, workerProps.getSleepTime().toString());
        }
        if(workerProps.getWorkerLogger() != null) {
            workerSession.setWorkerProperty(workerId, WORKER_KEY_WORKER_LOGGER, workerProps.getWorkerLogger());
        }
        // Reload
        getCurrentWorkerSession().reloadConfiguration(workerId);
    }

    private static void resetGlobalProperties(final int workerId) {
        final GlobalConfigurationSessionRemote globalConfigSession = getCurrentGlobalSession();
        final GlobalConfiguration gc = globalConfigSession.getGlobalConfiguration();
        final Enumeration<String> en = gc.getKeyEnumeration();
        while (en.hasMoreElements()) {
            String key = en.nextElement();
            if (key.toUpperCase(Locale.ENGLISH).startsWith("GLOB.WORKER" + workerId)) {
                key = key.substring("GLOB.".length());
                globalConfigSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, key);
            }
        }
    }

    /**
     * Removes the worker by resetting all of its properties.
     * @param workerId worker's identifier.
     */
    public static void removeWorkerById(final int workerId) {
        resetGlobalProperties(workerId);
        final WorkerSessionRemote workerSession = getCurrentWorkerSession();
        final WorkerConfig wc = workerSession.getCurrentWorkerConfig(workerId);
        LOG.info("Got current config before: " + wc.getProperties());
        for (Object o : wc.getProperties().keySet()) {
            final String key = (String) o;
            workerSession.removeWorkerProperty(workerId, key);
        }
        workerSession.reloadConfiguration(workerId);
        LOG.info("Got current config after: " + workerSession.getCurrentWorkerConfig(workerId).getProperties());
    }

}
