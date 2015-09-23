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
package org.signserver.server.log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.ejbca.util.CertTools;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ICertReqData;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.testutils.ModulesTestCase;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.ServiceConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.module.cmssigner.PlainSigner;
import org.signserver.server.IProcessable;
import org.signserver.server.cryptotokens.KeystoreCryptoToken;
import org.signserver.server.timedservices.hsmkeepalive.HSMKeepAliveTimedService;
import org.signserver.statusrepo.IStatusRepositorySession;

/**
 * Tests for audit logging using the System Logger.
 * 
 * Note: This test case assumes no other services are running concurrently 
 * producing output to signserver_audit.log.
 * 
 * @author Markus Kilås
 * @version $Id: SignServerCLITest.java 2815 2012-10-09 14:41:38Z malu9369 $
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SystemLoggingTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SystemLoggingTest.class);
    
    private static final String ENTRY_START_MARKER = "EVENT: ";
    
    private final int signerId = 6000;
    private final String signerName = "TestSigner6000";
    
    /** workers testing timed services audit logging */
    private static final int WORKERID_SERVICE = 5800;
    private static final int WORKERID_CRYPTOWORKER1 = 5801;
    private static final int WORKERID_CRYPTOWORKER2 = 5802;

    
    private File auditLogFile;
    private File keystoreFile;
    
    private final IWorkerSession workerSession = getWorkerSession();
    private final IGlobalConfigurationSession globalSession = getGlobalSession();
    private final IStatusRepositorySession statusSession = getStatusSession();
    
    @Before
    @Override
    public void setUp() throws Exception {
        auditLogFile = new File(getSignServerHome(), "signserver_audit.log");
        if (!auditLogFile.exists()) {
            final String error = "Test case requires Log4j to be configured for audit logging as described in the manual and with output to " + auditLogFile.getAbsolutePath() + " (or that being a symlink to the audit log file). The file is assumed to be truncated before (re)-starting the application server.";
            LOG.error(error);
            throw new Exception(error);
        }
        CertTools.installBCProviderIfNotAvailable();
    }
    
    @Test
    public void test00SetupDatabase() throws Exception {
        LOG.info(">test00SetupDatabase");
        addDummySigner(signerId, signerName, true);
        workerSession.setWorkerProperty(signerId, "WORKERLOGGER", "org.signserver.server.log.SecurityEventsWorkerLogger");
        workerSession.reloadConfiguration(signerId);
    }

    @Test
    public void test01ReadEntries() throws Exception {
        LOG.info(">test01ReadEntries");
        final File testFile = File.createTempFile("testreadentries", "tmp");
        testFile.deleteOnExit();
        final String line0 = "2012-10-19 10:51:43,240 INFO  [ISystemLogger] EVENT: GLOBAL_CONFIG_RELOAD; MODULE: GLOBAL_CONFIG; CUSTOM_ID: ; REPLY_TIME:1350636703240\n";
        final String line1 = "2012-10-19 10:51:43,277 INFO  [ISystemLogger] EVENT: SET_WORKER_CONFIG; MODULE: WORKER_CONFIG; CUSTOM_ID: 100; REPLY_TIME:1350636703277\n";
        final String line2 = "2012-10-19 10:51:44,048 INFO  [ISystemLogger] EVENT: CERTINSTALLED; MODULE: WORKER_CONFIG; CUSTOM_ID: 100; CERTIFICATE: Subject: CN=Anyone\n"
            + "Issuer: CN=Anyone\n"
            + "-----BEGIN CERTIFICATE-----\n"
            + "MIIBnTCCAQagAwIBAgIIFxjq8olIqcYwDQYJKoZIhvcNAQEFBQAwETEPMA0GA1UE\n"
            + "AwwGQW55b25lMB4XDTEyMTAxOTA4NTE0M1oXDTEzMTAxOTA4NTE0M1owETEPMA0G\n"
            + "A1UEAwwGQW55b25lMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCjkj6skp1w\n"
            + "NduK3lBUG9Gx72nH/vhR5p+zX8eCbOYIPQGT4GtHMZHaPzqMg/xmFxRFePovlN1l\n"
            + "l6a+1GOHv30wXDk+lu+Y1MUh24wbONj3g+j7pLz/sn4APxrZGrCwS/To6c3PhIwb\n"
            + "FsqWdXv+puFaWtipFBtVh7j4vQ2M6NJENQIDAQABMA0GCSqGSIb3DQEBBQUAA4GB\n"
            + "AFRT8DeFuAzWImZhjPpXN3L+0GSYoDtiL8k1ekpH/r17FEuzlYyCeUv5nh+jMgOU\n"
            + "vEMwq6WMvMRmMxSyh2125F00tdQgShvsuaZ3PG2OYdlYk9YhBHUtJm+Z7n2d0Aho\n"
            + "j6aIoPC6sBAsyrSumCWxVjZvgQNoefuN6I1/KpC7QVYP\n"
            + "-----END CERTIFICATE-----\n"
            + "; SCOPE: GLOB.; REPLY_TIME:1350636704048\n";
        final String line3 = "2012-10-19 10:51:44,130 INFO  [ISystemLogger] EVENT: SET_WORKER_CONFIG; MODULE: WORKER_CONFIG; CUSTOM_ID: 100; REPLY_TIME:1350636704130\n";
        
        PrintWriter writer = null;
        try {
            FileOutputStream fout = new FileOutputStream(testFile);
            writer = new PrintWriter(fout);
            
            // Adding 4 entries
            writer.print(line0);
            writer.print(line1);
            writer.print(line2);
            writer.print(line3);
            writer.flush();
            fout.getFD().sync();
            writer.close();
        } finally {
            if (writer != null) {
                writer.close();
            }
        }
        
        assertEquals("count entries", 4, readEntriesCount(testFile));
        List<String> lines = readEntries(testFile, 0, 1);
        assertEquals("read line0.count", 1, lines.size());
        assertEquals("read line0", line0, lines.get(0));
        
        lines = readEntries(testFile, 1, 1);
        assertEquals("read line1.count", 1, lines.size());
        assertEquals("read line1", line1, lines.get(0));
        
        lines = readEntries(testFile, 2, 1);
        assertEquals("read line2.count", 1, lines.size());
        assertEquals("read line2", line2, lines.get(0));
        
        lines = readEntries(testFile, 3, 1);
        assertEquals("read line3.count", 1, lines.size());
        assertEquals("read line3", line3, lines.get(0));
        
        lines = readEntries(testFile, 2, 2);
        assertEquals("read last2.count", 2, lines.size());
        assertEquals("read last2.1", line2, lines.get(0));
        assertEquals("read last2.2", line3, lines.get(1));
    }

    @Test
    public void test01LogStartup() throws Exception {
        LOG.info(">test01LogStartup");
        // Read second line of file (CESeCore outputs a time sync log line before the SignServer startup log line).
        LOG.info("Note: This test assumes the signserver_audit.log was cleared before the appserver started");
        List<String> lines = readEntries(auditLogFile, 0, 1);
        final String line0 = lines.get(0);
        LOG.info(line0);
        assertTrue("Contains event", line0.contains("EVENT: SIGNSERVER_STARTUP"));
        assertTrue("Contains module", line0.contains("MODULE: SERVICE"));
        assertTrue("Contains version", line0.contains("VERSION: "));
    }
    
    // Not easily tested
    // public void test01LogShutdown() throws Exception {
    //    fail("No implemented yet");
    // }
    @Test
    public void test01LogSetAndRemoveGlobalProperty() throws Exception {
        LOG.info(">test01LogSetAndRemoveGlobalProperty");
        final int linesBefore = readEntriesCount(auditLogFile);
        
        // Test setProperty
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "TESTPROPERTY47", "TESTVALUE47");
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 1);
        String line = lines.get(0);
        LOG.info(line);
        assertTrue("Contains event", line.contains("EVENT: SET_GLOBAL_PROPERTY"));
        assertTrue("Contains module", line.contains("MODULE: GLOBAL_CONFIG"));
        assertTrue("Contains value", line.contains("GLOBALCONFIG_VALUE: TESTVALUE47"));
        assertTrue("Contains property", line.contains("GLOBALCONFIG_PROPERTY: GLOB.TESTPROPERTY47"));
        
        // Test removeProperty
        globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "TESTPROPERTY47");
        lines = readEntries(auditLogFile, linesBefore + 1, 1);
        line = lines.get(0);
        LOG.info(line);
        assertTrue("Contains event", line.contains("EVENT: REMOVE_GLOBAL_PROPERTY"));
        assertTrue("Contains module", line.contains("MODULE: GLOBAL_CONFIG"));
        assertTrue("Contains property", line.contains("GLOBALCONFIG_PROPERTY: GLOB.TESTPROPERTY47"));
    }
    
    // Not easily tested
    // Running the below will cause other tests to fail as old workers
    // seems to be forgotten when the global session is reloaded
//    public void test01LogGlobalConfigReload() throws Exception {
//        final int linesBefore = readEntriesCount(auditLogFile);
//        
//        // Test reload
//        globalSession.reload();
//        
//        List<String> lines = readEntries(auditLogFile, linesBefore, 1);
//        String line = lines.get(0);
//        LOG.info(line);
//        assertTrue("Contains event", line.contains("EVENT: GLOBAL_CONFIG_RELOAD"));
//        assertTrue("Contains module", line.contains("MODULE: GLOBAL_CONFIG"));
//    }
    
    // Not easily tested
    // public void test01LogGlobalConfigResync() throws Exception {
    //    fail("No implemented yet");
    // }

    @Test
    public void test01LogSetAndRemoveWorkerProperty() throws Exception {
        LOG.info(">test01LogSetAndRemoveWorkerProperty");
        final int linesBefore = readEntriesCount(auditLogFile);
        
        // Test setProperty
        workerSession.setWorkerProperty(signerId, "TESTPROPERTY11", "TESTVALUE11");
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 1);
        String line = lines.get(0);
        LOG.info(line);
        assertTrue("Contains event", line.contains("EVENT: SET_WORKER_CONFIG"));
        assertTrue("Contains value", line.contains("added:TESTPROPERTY11: TESTVALUE11"));
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        
        // Test setting a new value
        workerSession.setWorkerProperty(signerId, "TESTPROPERTY11", "TESTVALUE4711");
        
        lines = readEntries(auditLogFile, linesBefore + 1, 1);
        line = lines.get(0);
        LOG.info(line);
        assertTrue("Contains event", line.contains("EVENT: SET_WORKER_CONFIG"));
        assertTrue("Contains value", line.contains("changed:TESTPROPERTY11: TESTVALUE4711"));
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        
        // Test removeProperty
        workerSession.removeWorkerProperty(signerId, "TESTPROPERTY11");
        lines = readEntries(auditLogFile, linesBefore + 2, 1);
        line = lines.get(0);
        LOG.info(line);
        
        assertTrue("Contains event", line.contains("EVENT: SET_WORKER_CONFIG"));
        assertTrue("Contains value", line.contains("removed:TESTPROPERTY11: TESTVALUE4711"));
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
    }
    
    @Test
    public void test01LogAddAuthorizedClient() throws Exception {
        LOG.info(">test01LogAddAuthorizedClient");
        final int linesBefore = readEntriesCount(auditLogFile);
        
        workerSession.addAuthorizedClient(signerId, new AuthorizedClient("1234567890", "CN=Test"));
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 1);
        String line = lines.get(0);
        LOG.info(line);
        assertTrue("Contains event", line.contains("EVENT: SET_WORKER_CONFIG"));
        assertTrue("Contains value", line.contains("added:authorized_client: SN: 1234567890, issuer DN: CN=Test"));
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
    }

    @Test
    public void test01LogRemoveAuthorizedClient() throws Exception {
        LOG.info(">test01LogRemoveAuthorizedClient");
        final int linesBefore = readEntriesCount(auditLogFile);
        
        workerSession.removeAuthorizedClient(signerId, new AuthorizedClient("1234567890", "CN=Test"));
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 1);
        String line = lines.get(0);
        LOG.info(line);
        assertTrue("Contains event", line.contains("EVENT: SET_WORKER_CONFIG"));
        assertTrue("Contains value", line.contains("removed:authorized_client: SN: 1234567890, issuer DN: CN=Test"));
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
    }

    @Test
    public void test01LogCertInstalled() throws Exception {
        LOG.info(">test01LogCertInstalled");
        int linesBefore = readEntriesCount(auditLogFile);
        
        // Test with uploadSignerCertificate method (global scope)
        final X509Certificate cert = new JcaX509CertificateConverter().getCertificate(new CertBuilder().build());
        workerSession.uploadSignerCertificate(signerId, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        String line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: CERTINSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        String certLine = new String(CertTools.getPEMFromCerts(Arrays.asList(cert))).replace("\r\n", "\n");
        assertTrue("Contains certificate", line.contains(certLine));
        assertTrue("Contains scope", line.contains("SCOPE: GLOBAL"));
        
        // Test removeProperty
        workerSession.removeWorkerProperty(signerId, "SIGNERCERT");
        lines = readEntries(auditLogFile, linesBefore + 2, 2);
        LOG.info(lines);
        
        line = getTheLineContaining(lines, "EVENT: CERTINSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        assertTrue("Contains empty certificate", line.contains("CERTIFICATE: ;"));
        assertTrue("Contains scope", line.contains("SCOPE: GLOBAL"));
        
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        
        
        // Test with uploadSignerCertificate method (node scope)
        linesBefore = readEntriesCount(auditLogFile);
        workerSession.uploadSignerCertificate(signerId, cert.getEncoded(), GlobalConfiguration.SCOPE_NODE);
        
        lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: CERTINSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        assertTrue("Contains certificate", line.contains(new String(CertTools.getPEMFromCerts(Arrays.asList(cert))).replace("\r\n", "\n")));
        assertTrue("Contains scope", line.contains("SCOPE: NODE"));
        assertTrue("Contains node", line.contains("NODE: " + WorkerConfig.getNodeId()));
        
        // Remove the property
        workerSession.removeWorkerProperty(signerId, WorkerConfig.getNodeId() + ".SIGNERCERT");
        
        
        // Test when setting the property manually (global scope)
        linesBefore = readEntriesCount(auditLogFile);
        workerSession.setWorkerProperty(signerId, "SIGNERCERT", new String(CertTools.getPEMFromCerts(Arrays.asList(cert))).replace("\r\n", "\n"));
        
        lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: CERTINSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        assertTrue("Contains certificate", line.contains(new String(CertTools.getPEMFromCerts(Arrays.asList(cert))).replace("\r\n", "\n")));
        assertTrue("Contains scope", line.contains("SCOPE: GLOBAL"));
        
        // Remove the property
        workerSession.removeWorkerProperty(signerId, "SIGNERCERT");
        
        
        // Test when setting the property manually (node scope)
        linesBefore = readEntriesCount(auditLogFile);
        workerSession.setWorkerProperty(signerId, "NODE47.SIGNERCERT", new String(CertTools.getPEMFromCerts(Arrays.asList(cert))).replace("\r\n", "\n"));
        
        lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: CERTINSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        assertTrue("Contains certificate", line.contains(new String(CertTools.getPEMFromCerts(Arrays.asList(cert))).replace("\r\n", "\n")));
        assertTrue("Contains scope", line.contains("SCOPE: NODE"));
        assertTrue("Contains node", line.contains("NODE: NODE47"));
        
        // Remove the property
        workerSession.removeWorkerProperty(signerId, "NODE47.SIGNERCERT");
    }

    @Test
    public void test01LogCertChainInstalled() throws Exception {
        LOG.info(">test01LogCertChainInstalled");
        int linesBefore = readEntriesCount(auditLogFile);
        
        // Test with uploadSignerCertificateChain method (global scope)
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        final X509Certificate issuerCert = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSelfSignKeyPair(issuerKeyPair).setSubject("CN=Issuer, C=SE").build());
        final X509Certificate cert = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubject("CN=Signer,C=SE").setIssuer("CN=Issuer, C=SE").build());
        workerSession.uploadSignerCertificateChain(signerId, Arrays.asList(cert.getEncoded(), issuerCert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        String line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: CERTCHAININSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        assertTrue("Contains certificate", line.contains(new String(CertTools.getPEMFromCerts(Arrays.asList(cert, issuerCert))).replace("\r\n", "\n")));
        assertTrue("Contains scope", line.contains("SCOPE: GLOBAL"));
        
        // Test removeProperty
        if (!workerSession.removeWorkerProperty(signerId, "SIGNERCERTCHAIN")) {
            throw new Exception("Property could not be removed");
        }
        lines = readEntries(auditLogFile, linesBefore + 2, 2);
        LOG.info(lines);
        
        line = getTheLineContaining(lines, "EVENT: CERTCHAININSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        assertTrue("Contains empty certificate chain", line.contains("CERTIFICATECHAIN: ;"));
        assertTrue("Contains scope", line.contains("SCOPE: GLOBAL"));
        
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        
        
        // Test with uploadSignerCertificateChain method (node scope)
        linesBefore = readEntriesCount(auditLogFile);
        workerSession.uploadSignerCertificateChain(signerId, Arrays.asList(cert.getEncoded(), issuerCert.getEncoded()), GlobalConfiguration.SCOPE_NODE);
        
        lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: CERTCHAININSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        assertTrue("Contains certificate", line.contains(new String(CertTools.getPEMFromCerts(Arrays.asList(cert, issuerCert))).replace("\r\n", "\n")));
        assertTrue("Contains scope", line.contains("SCOPE: NODE"));
        assertTrue("Contains node", line.contains("NODE: " + WorkerConfig.getNodeId()));
        
        // Remove the property
        workerSession.removeWorkerProperty(signerId, "SIGNERCERTCHAIN");
        
        
        // Test when setting the property manually (global scope)
        linesBefore = readEntriesCount(auditLogFile);
        workerSession.setWorkerProperty(signerId, "SIGNERCERTCHAIN", new String(CertTools.getPEMFromCerts(Arrays.asList(cert, issuerCert))).replace("\r\n", "\n"));
        
        lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: CERTCHAININSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        assertTrue("Contains certificate", line.contains(new String(CertTools.getPEMFromCerts(Arrays.asList(cert, issuerCert))).replace("\r\n", "\n")));
        assertTrue("Contains scope", line.contains("SCOPE: GLOBAL"));
        
        // Remove the property
        if (!workerSession.removeWorkerProperty(signerId, "SIGNERCERTCHAIN")) {
            throw new Exception("Could not remove property");
        }
        
        
        // Test when setting the property manually (node scope)
        linesBefore = readEntriesCount(auditLogFile);
        workerSession.setWorkerProperty(signerId, "NODE47.SIGNERCERTCHAIN", new String(CertTools.getPEMFromCerts(Arrays.asList(cert, issuerCert))).replace("\r\n", "\n"));
        
        lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: CERTCHAININSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        assertTrue("Contains certificate", line.contains(new String(CertTools.getPEMFromCerts(Arrays.asList(cert, issuerCert))).replace("\r\n", "\n")));
        assertTrue("Contains scope", line.contains("SCOPE: NODE"));
        assertTrue("Contains node", line.contains("NODE: NODE47"));
        
        // Remove the property
        workerSession.removeWorkerProperty(signerId, "NODE47.SIGNERCERTCHAIN");
    }

    private void setupCryptoToken(int tokenId, String tokenName, String pin) throws Exception {
        // Create keystore
        keystoreFile = File.createTempFile("testkeystore", ".p12");
        FileOutputStream out = null;
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(null, null);
            out = new FileOutputStream(keystoreFile);
            ks.store(out, pin.toCharArray());
        } finally {
            IOUtils.closeQuietly(out);
        }

        // Setup crypto token
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + tokenId + ".CLASSPATH", "org.signserver.server.signers.CryptoWorker");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + tokenId + ".SIGNERTOKEN.CLASSPATH", KeystoreCryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, "NAME", tokenName);
        workerSession.setWorkerProperty(tokenId, "KEYSTORETYPE", "PKCS12");
        workerSession.setWorkerProperty(tokenId, "KEYSTOREPATH", keystoreFile.getAbsolutePath());
        workerSession.setWorkerProperty(tokenId, "KEYSTOREPASSWORD", pin);
        workerSession.reloadConfiguration(tokenId);
    }
    
    /**
     * Tests that importing a certificate chain to a token is audit logged
     * including the complete chain.
     * @throws Exception 
     */
    @Test
    public void test01LogCertChainInstalledToToken() throws Exception {
        LOG.info(">test01LogCertChainInstalledToToken");
        
        final String tokenName = "TestCryptoTokenP12_001";
        final String alias = "testkeyalias10";
        
        try {
            setupCryptoToken(WORKERID_CRYPTOWORKER1, tokenName, "foo123");
            workerSession.generateSignerKey(WORKERID_CRYPTOWORKER1, "RSA", "512", alias, null);
            
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=testkeyalias10,C=SE", null);
            ICertReqData req = workerSession.getCertificateRequest(WORKERID_CRYPTOWORKER1, certReqInfo, false);
            Base64SignerCertReqData reqData = (Base64SignerCertReqData) req;
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
            
            int linesBefore = readEntriesCount(auditLogFile);

            // Test with uploadSignerCertificateChain method (global scope)
            KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
            final X509Certificate issuerCert = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSelfSignKeyPair(issuerKeyPair).setSubject("CN=Issuer, C=SE").build());
            final X509Certificate cert = new JcaX509CertificateConverter().getCertificate(new X509v3CertificateBuilder(new X500Name("CN=Issuer, C=SE"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate())));
            
            workerSession.importCertificateChain(WORKERID_CRYPTOWORKER1, Arrays.asList(cert.getEncoded(), issuerCert.getEncoded()), alias, null);

            List<String> lines = readEntries(auditLogFile, linesBefore, 2);
            LOG.info(lines);

            String line = getTheLineContaining(lines, "EVENT: CERTCHAININSTALLED");
            assertNotNull("Contains event", line);
            assertTrue("Contains module", line.contains("MODULE: KEY_MANAGEMENT"));
            assertTrue("Contains worker id", line.contains("WORKER_ID: " + WORKERID_CRYPTOWORKER1));
            assertTrue("Contains crypto token", line.contains("CRYPTOTOKEN: " + tokenName));
            assertTrue("Contains key alias", line.contains("KEYALIAS: " + alias));
            assertTrue("Contains certificate", line.contains(new String(org.cesecore.util.CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(cert, issuerCert))).replace("\r\n", "\n")));
        } finally {
            removeWorker(WORKERID_CRYPTOWORKER1);
            if (keystoreFile != null) {
                FileUtils.deleteQuietly(keystoreFile);
            }
        }
    }

    @Test
    public void test01LogKeySelected() throws Exception {
        LOG.info(">test01LogKeySelected");
        // Test when setting the property manually (global scope)
        int linesBefore = readEntriesCount(auditLogFile);
        workerSession.setWorkerProperty(signerId, "DEFAULTKEY", "ts_key00002");
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        String line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: KEYSELECTED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        assertTrue("Contains key alias", line.contains("KEYALIAS: ts_key00002"));
        assertTrue("Contains crypto token", line.contains("CRYPTOTOKEN: " + signerName));
        assertTrue("Contains scope", line.contains("SCOPE: GLOBAL"));
        
        // Remove the property
        if (!workerSession.removeWorkerProperty(signerId, "DEFAULTKEY")) {
            throw new Exception("Could not remove property");
        }
        
        lines = readEntries(auditLogFile, linesBefore + 2, 3);
        LOG.info(lines);
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: KEYSELECTED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        assertTrue("Contains key alias", line.contains("KEYALIAS: ;"));
        assertTrue("Contains crypto token", line.contains("CRYPTOTOKEN: " + signerName));
        assertTrue("Contains scope", line.contains("SCOPE: GLOBAL"));
        
        
        // Test when setting the property manually (node scope)
        linesBefore = readEntriesCount(auditLogFile);
        workerSession.setWorkerProperty(signerId, "NODE47.DEFAULTKEY", "ts_key00003");
        
        lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: KEYSELECTED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains key alias", line.contains("KEYALIAS: ts_key00003"));
        assertTrue("Contains crypto token", line.contains("CRYPTOTOKEN: " + signerName));
        assertTrue("Contains scope", line.contains("SCOPE: NODE"));
        assertTrue("Contains node", line.contains("NODE: NODE47"));
        
        // Remove the property
        workerSession.removeWorkerProperty(signerId, "NODE47.DEFAULTKEY");
        
        // Reset defaultkey
        workerSession.setWorkerProperty(signerId, "DEFAULTKEY", "Signer 1");
    }

    @Test
    public void test01LogKeyGenAndTestAndCSR() throws Exception {
        LOG.info(">test01LogKeyGenAndTestAndCSR");
        final String signerName = "TestKeyGenAndCSR1";
        final int p12SignerId = 5980;
        try {
            // Copy sample P12 to a temporary P12
            File sampleP12 = new File(getSignServerHome(), "res/test/dss10/dss10_signer3.p12");
            final String keyInKeystore = "Signer 3";
            File p12 = File.createTempFile("testkeystore", "tmp");
            p12.deleteOnExit();
            KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
            FileInputStream fin = null;
            FileOutputStream fout = null;
            try {
                fin = new FileInputStream(sampleP12);
                fout = new FileOutputStream(p12);
                keystore.load(fin, "foo123".toCharArray());
                keystore.store(fout, "foo123".toCharArray());
            } finally {
                if (fin != null) {
                    try {
                        fin.close();
                    } catch (IOException ignored) {} // NOPMD
                }
                if (fout != null) {
                    try {
                        fout.close();
                    } catch (IOException ignored) {} // NOPMD
                }
            }
            
            // Add signer using the P12
            addP12DummySigner(p12SignerId, signerName, p12, "foo123", keyInKeystore);
            
            // Test keygen
            int linesBefore = readEntriesCount(auditLogFile);
            workerSession.generateSignerKey(p12SignerId, "RSA", "512", "ts_key00004", "foo123".toCharArray());
            workerSession.generateSignerKey(p12SignerId, "RSA", "512", "additionalKey", "foo123".toCharArray());

            List<String> lines = readEntries(auditLogFile, linesBefore, 1);
            LOG.info(lines);
            String line = lines.get(0);
            assertTrue("Contains event", line.contains("EVENT: KEYGEN"));
            assertTrue("Contains module", line.contains("MODULE: KEY_MANAGEMENT"));
            assertTrue("Contains worker id", line.contains("WORKER_ID: " + p12SignerId));
            assertTrue("Contains alias", line.contains("KEYALIAS: ts_key00004"));
            assertTrue("Contains spec", line.contains("KEYSPEC: 512"));
            assertTrue("Contains alg", line.contains("KEYALG: RSA"));
            assertTrue("Contains crypto token", line.contains("CRYPTOTOKEN: " + signerName));

            // Test keytest
            workerSession.activateSigner(p12SignerId, "foo123");
            workerSession.testKey(p12SignerId, "ts_key00004", "foo123".toCharArray());
            
            lines = readEntries(auditLogFile, linesBefore + 2, 1);
            LOG.info(lines);
            line = lines.get(0);
            assertTrue("Contains event", line.contains("EVENT: KEYTEST"));
            assertTrue("Contains module", line.contains("MODULE: KEY_MANAGEMENT"));
            assertTrue("Contains worker id", line.contains("WORKER_ID: " + p12SignerId));
            assertTrue("Contains key alias", line.contains("KEYALIAS: ts_key00004"));
            assertTrue("Contains crypto token", line.contains("CRYPTOTOKEN: " + signerName));
            assertTrue("Contains test results", line.contains("KeyTestResult{alias=ts_key00004, success=true"));
            
            // Test key with all, to assure not extra base 64 encoding is done
            workerSession.testKey(p12SignerId, "all", "foo123".toCharArray());
            lines = readEntries(auditLogFile, linesBefore + 3, 1);
            LOG.info(lines);
            line = lines.get(0);
            assertTrue("Contains test results", line.contains("KeyTestResult{alias=ts_key00004, success=true"));
            
            // Test gencsr
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=TS Signer 1,C=SE", null);
            ICertReqData req = workerSession.getCertificateRequest(p12SignerId, certReqInfo, false);
            Base64SignerCertReqData reqData = (Base64SignerCertReqData) req;
            lines = readEntries(auditLogFile, linesBefore + 4, 1);
            LOG.info(lines);
            line = lines.get(0);
            assertTrue("Contains event", line.contains("EVENT: GENCSR"));
            assertTrue("Contains module", line.contains("MODULE: KEY_MANAGEMENT"));
            assertTrue("Contains worker id", line.contains("WORKER_ID: " + p12SignerId));
            assertTrue("Contains crypto token", line.contains("CRYPTOTOKEN: " + signerName));
            assertTrue("Contains key alias: " + line, line.contains("KEYALIAS: " + keyInKeystore));
            assertTrue("Contains for default key: " + line, line.contains("FOR_DEFAULTKEY: true"));
            assertTrue("Contains csr", line.contains("CSR: " + new String(reqData.getBase64CertReq())));
            
            // Test gencsr            
            req = workerSession.getCertificateRequest(p12SignerId, certReqInfo, false, "ts_key00004");
            reqData = (Base64SignerCertReqData) req;
            lines = readEntries(auditLogFile, linesBefore + 5, 1);
            LOG.info(lines);
            line = lines.get(0);
            assertTrue("Contains event", line.contains("EVENT: GENCSR"));
            assertTrue("Contains module", line.contains("MODULE: KEY_MANAGEMENT"));
            assertTrue("Contains worker id", line.contains("WORKER_ID: " + p12SignerId));
            assertTrue("Contains crypto token", line.contains("CRYPTOTOKEN: " + signerName));
            assertTrue("Contains key alias: " + line, line.contains("KEYALIAS: ts_key00004"));
            assertTrue("Contains for default key: " + line, line.contains("FOR_DEFAULTKEY: false"));
            assertTrue("Contains csr", line.contains("CSR: " + new String(reqData.getBase64CertReq())));
            
            // Test remove key
            workerSession.removeKey(p12SignerId, "ts_key00004");
            lines = readEntries(auditLogFile, linesBefore + 6, 1);
            LOG.info(lines);
            line = lines.get(0);
            assertTrue("Contains event", line.contains("EVENT: KEYREMOVE"));
            assertTrue("Contains module", line.contains("MODULE: KEY_MANAGEMENT"));
            assertTrue("Contains worker id", line.contains("WORKER_ID: " + p12SignerId));
            assertTrue("Contains crypto token", line.contains("CRYPTOTOKEN: " + signerName));
            assertTrue("Contains key alias: " + line, line.contains("KEYALIAS: ts_key00004"));
            
        } finally {
            removeWorker(p12SignerId);
        }
    }
    
    @Test
    public void test01LogKeyGenAndTestAndCSR_separateToken() throws Exception {
        LOG.info(">test01LogKeyGenAndTestAndCSR_separateToken");
        
        final int workerId = 5881;
        final String tokenName = "TestKeyGenAndCSR2";
        final int p12SignerId = 5880;
        
        try {
            // Copy sample P12 to a temporary P12
            File sampleP12 = new File(getSignServerHome(), "res/test/dss10/dss10_signer3.p12");
            File p12 = File.createTempFile("testkeystore", "tmp");
            p12.deleteOnExit();
            KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
            FileInputStream fin = null;
            FileOutputStream fout = null;
            try {
                fin = new FileInputStream(sampleP12);
                fout = new FileOutputStream(p12);
                keystore.load(fin, "foo123".toCharArray());
                keystore.store(fout, "foo123".toCharArray());
            } finally {
                if (fin != null) {
                    try {
                        fin.close();
                    } catch (IOException ignored) {} // NOPMD
                }
                if (fout != null) {
                    try {
                        fout.close();
                    } catch (IOException ignored) {} // NOPMD
                }
            }
            
            // Add crypto worker using the P12
            addP12DummySigner(p12SignerId, tokenName, p12, "foo123", null);
            
            // Add a separate worker
            getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL,
            "WORKER" + workerId + ".CLASSPATH", PlainSigner.class.getName());
            getWorkerSession().setWorkerProperty(workerId, "NAME", "TheWorker" + workerId);
            getWorkerSession().setWorkerProperty(workerId, "AUTHTYPE", IProcessable.AUTHTYPE_NOAUTH);
            getWorkerSession().setWorkerProperty(workerId, "CRYPTOTOKEN", tokenName);
            getWorkerSession().reloadConfiguration(workerId);

            // Test keygen
            int linesBefore = readEntriesCount(auditLogFile);
            workerSession.generateSignerKey(workerId, "RSA", "512", "ts_key00004", "foo123".toCharArray());
            workerSession.generateSignerKey(workerId, "RSA", "512", "additionalKey", "foo123".toCharArray());

            List<String> lines = readEntries(auditLogFile, linesBefore, 1);
            LOG.info(lines);
            String line = lines.get(0);
            assertTrue("Contains event", line.contains("EVENT: KEYGEN"));
            assertTrue("Contains module", line.contains("MODULE: KEY_MANAGEMENT"));
            assertTrue("Contains worker id", line.contains("WORKER_ID: " + workerId));
            assertTrue("Contains key alias", line.contains("KEYALIAS: ts_key00004"));
            assertTrue("Contains spec", line.contains("KEYSPEC: 512"));
            assertTrue("Contains alg", line.contains("KEYALG: RSA"));
            assertTrue("Contains crypto token", line.contains("CRYPTOTOKEN: " + tokenName));

            // Test keytest
            workerSession.activateSigner(workerId, "foo123");
            workerSession.testKey(workerId, "ts_key00004", "foo123".toCharArray());
            
            lines = readEntries(auditLogFile, linesBefore + 2, 1);
            LOG.info(lines);
            line = lines.get(0);
            assertTrue("Contains event", line.contains("EVENT: KEYTEST"));
            assertTrue("Contains module", line.contains("MODULE: KEY_MANAGEMENT"));
            assertTrue("Contains worker id", line.contains("WORKER_ID: " + workerId));
            assertTrue("Contains key alias", line.contains("KEYALIAS: ts_key00004"));
            assertTrue("Contains crypto token", line.contains("CRYPTOTOKEN: " + tokenName));
            assertTrue("Contains test results", line.contains("KeyTestResult{alias=ts_key00004, success=true"));
            
            // Test key with all, to assure not extra base 64 encoding is done
            workerSession.testKey(workerId, "all", "foo123".toCharArray());
            lines = readEntries(auditLogFile, linesBefore + 3, 1);
            LOG.info(lines);
            line = lines.get(0);
            assertTrue("Contains test results", line.contains("KeyTestResult{alias=ts_key00004, success=true"));
            
            // Test gencsr
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=TS Signer 1,C=SE", null);
            ICertReqData req = workerSession.getCertificateRequest(workerId, certReqInfo, false, "ts_key00004");
            Base64SignerCertReqData reqData = (Base64SignerCertReqData) req;
            lines = readEntries(auditLogFile, linesBefore + 4, 1);
            LOG.info(lines);
            line = lines.get(0);
            assertTrue("Contains event", line.contains("EVENT: GENCSR"));
            assertTrue("Contains module", line.contains("MODULE: KEY_MANAGEMENT"));
            assertTrue("Contains worker id", line.contains("WORKER_ID: " + workerId));
            assertTrue("Contains crypto token", line.contains("CRYPTOTOKEN: " + tokenName));
            assertTrue("Contains key alias", line.contains("KEYALIAS: ts_key00004"));
            assertTrue("Contains for default key: " + line, line.contains("FOR_DEFAULTKEY: false"));
            assertTrue("Contains csr", line.contains("CSR: " + new String(reqData.getBase64CertReq())));
            
            // Test remove key
            workerSession.removeKey(workerId, "ts_key00004");
            lines = readEntries(auditLogFile, linesBefore + 5, 1);
            LOG.info(lines);
            line = lines.get(0);
            assertTrue("Contains event", line.contains("EVENT: KEYREMOVE"));
            assertTrue("Contains module", line.contains("MODULE: KEY_MANAGEMENT"));
            assertTrue("Contains worker id", line.contains("WORKER_ID: " + workerId));
            assertTrue("Contains crypto token", line.contains("CRYPTOTOKEN: " + tokenName));
            assertTrue("Contains key alias: " + line, line.contains("KEYALIAS: ts_key00004"));
        } finally {
            removeWorker(workerId);
            removeWorker(p12SignerId);
        }
    }

    @Test
    public void test01LogSetStatusProperty() throws Exception {
        LOG.info(">test01LogSetStatusProperty");
        int linesBefore = readEntriesCount(auditLogFile);
        final long expiration = System.currentTimeMillis() + 1000;
        statusSession.update("TEST_PROPERTY1", "TESTVALUE47", expiration);
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 1);
        String line = lines.get(0);
        LOG.info(line);
        assertTrue("Contains event", line.contains("EVENT: SET_STATUS_PROPERTY"));
        assertTrue("Contains module", line.contains("MODULE: STATUS_REPOSITORY"));
        assertTrue("Contains property", line.contains("STATUSREPO_PROPERTY: TEST_PROPERTY1"));
        assertTrue("Contains value", line.contains("STATUSREPO_VALUE: TESTVALUE47"));
        assertTrue("Contains expiration", line.contains("STATUSREPO_EXPIRATION: " + expiration));
    }

    @Test
    public void test01LogProcessWorkerNotFound() throws Exception {
        LOG.info(">test01LogProcessWorkerNotFound");
        int linesBefore = readEntriesCount(auditLogFile);
        
        final int nonExistingWorkerId = 1234567;
        try {
            workerSession.process(nonExistingWorkerId, new GenericSignRequest(123, "<a/>".getBytes()), new RequestContext());
            throw new Exception("Should have failed as it was a request to non existing worker");
        } catch (IllegalRequestException ignored) { //NOPMD
            // OK
        }
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 1);
        String line = lines.get(0);
        LOG.info(line);
        assertTrue("Contains event", line.contains("EVENT: PROCESS"));
        assertTrue("Contains module", line.contains("MODULE: WORKER"));
        assertTrue("Contains no correct worker id", line.contains("WORKER_ID: "));
        assertTrue("Contains log id", line.contains("LOG_ID: "));
        assertTrue("Contains success false", line.contains("PROCESS_SUCCESS: false"));
        assertTrue("Contains exception", line.contains("EXCEPTION: No such worker: 1234567"));
    }

    @Test
    public void test01LogWorkerConfigReload() throws Exception {
        LOG.info(">test01LogWorkerConfigReload");
        int linesBefore = readEntriesCount(auditLogFile);
        
        workerSession.reloadConfiguration(signerId);
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 1);
        String line = lines.get(0);
        LOG.info(line);
        assertTrue("Contains event", line.contains("EVENT: RELOAD_WORKER_CONFIG"));
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains no correct worker id", line.contains("WORKER_ID: "));
        assertTrue("Contains admin", line.contains("ADMINISTRATOR: CLI user"));
    }
    
    /**
     * Test that the SecurityEventsWorkerLogger is properly audit-logging process requests.
     * @throws Exception
     */
    @Test
    public void test01WorkerProcess() throws Exception {
        LOG.info(">test01WorkerProcess");
        int linesBefore = readEntriesCount(auditLogFile);
        
        GenericSignRequest request = new GenericSignRequest(123, "<test/>".getBytes("UTF-8"));
        workerSession.process(signerId, request, new RequestContext());
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 1);
        String line = lines.get(0);
        LOG.info(line);
        assertTrue("Contains event", line.contains("EVENT: PROCESS"));
        assertTrue("Contains module", line.contains("MODULE: WORKER"));
        assertTrue("Contains success", line.contains("PROCESS_SUCCESS: true"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        assertTrue("Contains log id", line.contains("LOG_ID:"));
        assertTrue("Contains client ip", line.contains("CLIENT_IP:"));
    }
    
    /**
     * Test logging with excluded fields.
     * @throws Exception
     */
    @Test
    public void test02WorkerProcessExcludeFields() throws Exception {
        LOG.info(">test02WorkerProcessExcludeFields");
        setLoggingFields(null, "CLIENT_IP, LOG_ID");
        
        int linesBefore = readEntriesCount(auditLogFile);
        
        GenericSignRequest request = new GenericSignRequest(123, "<test/>".getBytes("UTF-8"));
        workerSession.process(signerId, request, new RequestContext());
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 1);
        String line = lines.get(0);
        LOG.info(line);
        // check that the excluded fields are not present
        assertFalse("Shouldn't contain excluded field", line.contains("CLIENT_IP:"));
        assertFalse("Shouldn't contain excluded field", line.contains("LOG_ID:"));
        // ensure that some other field didn't get excluded as well...
        assertTrue("Should contain non-excluded field", line.contains("REQUESTID:"));
    }
    
    /**
     * Test logging with included fields.
     * @throws Exception
     */
    @Test
    public void test03WorkerProcessIncludeFields() throws Exception {
        LOG.info(">test03WorkerProcessIncludeFields");
        setLoggingFields("CLIENT_IP, LOG_ID", null);
        
        int linesBefore = readEntriesCount(auditLogFile);
        
        GenericSignRequest request = new GenericSignRequest(123, "<test/>".getBytes("UTF-8"));
        workerSession.process(signerId, request, new RequestContext());
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 1);
        String line = lines.get(0);
        LOG.info(line);
        assertTrue("Should contain included field", line.contains("CLIENT_IP:"));
        assertTrue("Should contain included field", line.contains("LOG_ID:"));
        assertFalse("Shouldn't contain non-included field", line.contains("FILENAME:"));
    }
    
    /**
     * Test that setting both include and exclude fails.
     * @throws Exception
     */
    @Test
    public void test04WorkerProcessIncludeExcludeFields() throws Exception {
        LOG.info(">test04WorkerProcessIncludeExcludeFields");
        setLoggingFields("CLIENT_IP", "LOG_ID");
        
        try {
            GenericSignRequest request = new GenericSignRequest(123, "<test/>".getBytes("UTF-8"));
            workerSession.process(signerId, request, new RequestContext());
        } catch (SignServerException e) {
            // expected
            return;
        }
        
        fail("Should fail with inproperly configured logger");
    }
    
    /**
     * Test that the SecurityEventsWorkerLogger is properly audit-logging process requests with failed status.
     * @throws Exception
     */
    @Test
    public void test05WorkerProcessNonSucess() throws Exception {
        LOG.info(">test05WorkerProcessNonSucess");
        // reset logging fields (all fields being logged)
        setLoggingFields(null, null);
        int linesBefore = readEntriesCount(auditLogFile);
        
        try {
            GenericSignRequest request = new GenericSignRequest(123, "bogus".getBytes("UTF-8"));
            workerSession.process(signerId, request, new RequestContext());
        } catch (IllegalRequestException e) {
            // expected
        }

        List<String> lines = readEntries(auditLogFile, linesBefore, 1);
        String line = lines.get(0);
        LOG.info(line);
        assertTrue("Contains event", line.contains("EVENT: PROCESS"));
        assertTrue("Contains module", line.contains("MODULE: WORKER"));
        assertTrue("Contains success", line.contains("PROCESS_SUCCESS: false"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        assertTrue("Contains log id", line.contains("LOG_ID:"));
        assertTrue("Contains client ip", line.contains("CLIENT_IP:"));
    }

    /**
     * Test the SECURE_AUDITLOGGING WORKLOG_TYPES option for the HSM keep-alive
     * timed service. This is done in this test since audit logging is set up
     * here.
     * 
     * @throws Exception 
     */
    @Test
    public void test06TimedServiceWithAuditLogging() throws Exception {
        LOG.info(">test06TimedServiceWithAuditLogging");
        try {
            setProperties(new File(getSignServerHome(), "res/test/test-hsmkeepalive-configuration.properties"));
            workerSession.setWorkerProperty(WORKERID_SERVICE,
                    HSMKeepAliveTimedService.CRYPTOTOKENS, "");
            workerSession.setWorkerProperty(WORKERID_SERVICE,
                    ServiceConfig.WORK_LOG_TYPES, "SECURE_AUDITLOGGING");
            workerSession.reloadConfiguration(WORKERID_SERVICE);
             
            int linesBefore = readEntriesCount(auditLogFile);
            final String line = waitForNextLine(linesBefore, 30);

            if (line != null) {
                LOG.info(line);
                assertTrue("Contains event", line.contains("EVENT: TIMED_SERVICE_RUN"));
                assertTrue("Contains module", line.contains("MODULE: SERVICE"));
                assertTrue("Contains worker",
                        line.contains("WORKER_ID: " + WORKERID_SERVICE));
            } else {
                fail("No audit log entry for service invocation found");
            }
        } finally {
            removeWorker(WORKERID_SERVICE);
            removeWorker(WORKERID_CRYPTOWORKER1);
            removeWorker(WORKERID_CRYPTOWORKER2);
        }
    }
    
     /**
     * Test that the SecurityEventsWorkerLogger is properly audit-logging process requests.
     * @throws Exception
     */
    @Test
    public void test07WorkerProcessKeyAlias() throws Exception {
        LOG.info(">test07WorkerProcessKeyAlias");
        int linesBefore = readEntriesCount(auditLogFile);
        
        GenericSignRequest request = new GenericSignRequest(123, "<test/>".getBytes("UTF-8"));
        workerSession.process(signerId, request, new RequestContext());
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 1);
        String line = lines.get(0);
        LOG.info(line);
        assertTrue("Contains event", line.contains("EVENT: PROCESS"));
        assertTrue("Contains module", line.contains("MODULE: WORKER"));
        assertTrue("Contains success", line.contains("PROCESS_SUCCESS: true"));
        assertTrue("Contains worker id", line.contains("WORKER_ID: " + signerId));
        assertTrue("Contains key alias", line.contains("KEYALIAS: " + getSigner1KeyAlias()));
        assertTrue("Contains crypto token", line.contains("CRYPTOTOKEN: " + signerName));
    }
    
    private String waitForNextLine(final int linesBefore, final int maxTries) throws Exception {
        try {
            for (int i = 0; i < maxTries; i++) {
                final List<String> lines =
                        readEntries(auditLogFile, linesBefore, 1);
                
                if (!lines.isEmpty()) {
                    return lines.get(0);
                }
                
                Thread.sleep(1000);
            }
        } catch (InterruptedException ex) {
            LOG.error("Interrupted", ex);
        }
        
        return null;
    }
    
    @Test
    public void test99TearDownDatabase() throws Exception {
        LOG.info(">test99TearDownDatabase");
        removeWorker(signerId);
    }

    private void setLoggingFields(final String includeFields, final String excludeFields) {
        if (includeFields != null) {
            workerSession.setWorkerProperty(signerId, "LOGINCLUDEFIELDS", includeFields);
        } else {
            workerSession.removeWorkerProperty(signerId, "LOGINCLUDEFIELDS");
        }
        if (excludeFields != null) {
            workerSession.setWorkerProperty(signerId, "LOGEXCLUDEFIELDS", excludeFields);
        } else {
            workerSession.removeWorkerProperty(signerId, "LOGEXCLUDEFIELDS");
        }
        workerSession.reloadConfiguration(signerId);
    }
    
    private int readEntriesCount(final File file) throws Exception {
        int result = 0;
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(ENTRY_START_MARKER)) {
                    result++;
                }
            }
            return result;
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }
    
    private List<String> readEntries(final File file, final int skipLines, final int maxLines) throws Exception {
        LOG.info(">readEntries(" + skipLines + ", " + maxLines + ")");
        final ArrayList results = new ArrayList(maxLines);
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(file));
            StringBuilder entry = null;
            String line;
            int entryIndex = -1;
            while ((line = reader.readLine()) != null && results.size() < maxLines) {
                if (line.contains(ENTRY_START_MARKER)) {
                    entryIndex++;
                }
                
                if (entryIndex >= skipLines) {
                    if (line.contains(ENTRY_START_MARKER)) {
                        if (entry != null) {
                            // Store the previous entry
                            results.add(entry.toString());
                        }
                        // Start new entry
                        entry = new StringBuilder();
                    }
                    entry.append(line).append("\n");
                }
                
            }
            if (results.size() < maxLines && entry != null && entry.length() > 0) {
                results.add(entry.toString());
            }
            return results;
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }
    
    private String getTheLineContaining(List<String> lines, String token) {
        String result = null;
        for (String line : lines) {
            if (line.contains(token)) {
                if (result == null) {
                    result = line;
                } else {
                    fail("Multiple lines containing \"" + token + "\" found");
                }
            }
        }
        return result;
    }
    
}
