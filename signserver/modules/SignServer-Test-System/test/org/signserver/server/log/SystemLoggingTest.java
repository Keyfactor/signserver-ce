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
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.ejbca.util.CertTools;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ICertReqData;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;

/**
 * TODO.
 * 
 * Note: This test case assumes no other services are running concurrently 
 * producing output to signserver_audit.log.
 * 
 * @author Markus Kilås
 * @version $Id: SignServerCLITest.java 2815 2012-10-09 14:41:38Z malu9369 $
 */
public class SystemLoggingTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SystemLoggingTest.class);
    
    private static final String ENTRY_START_MARKER = "EVENT: ";
    
    private final int signerId = getSignerIdDummy1();
    
    private File auditLogFile;
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        
        auditLogFile = new File(getSignServerHome(), "signserver_audit.log");
        if (!auditLogFile.exists()) {
            final String error = "Test case requires Log4j to be configured for audit logging as described in the manual and with output to " + auditLogFile.getAbsolutePath() + " (or that being a symlink to the audit log file). The file is assumed to be truncated before (re)-starting the application server.";
            LOG.error(error);
            throw new Exception(error);
        }
        
        CertTools.installBCProviderIfNotAvailable();
    }

    @Override
    protected void tearDown() throws Exception {
        // For some reason we need to reload the global configuration after the
        // tests otherwise it is left in some bad state
        globalSession.reload();
    }
    
    public void test00SetupDatabase() throws Exception {
        addSoftDummySigner(getSignerIdDummy1(), getSignerNameDummy1());
    }
    
    public void testReadEntries() throws Exception {
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
        System.out.println("Got: \"" + lines + "\"");
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
    
    /**
     * 
     * 
     * <pre>2012-10-19 08:37:32,213 INFO  [ISystemLogger] EVENT: SIGNSERVER_STARTUP; MODULE: SERVICE; CUSTOM_ID: ; VERSION: SignServer 3.3.0alpha12; REPLY_TIME:1350628652213</pre>
     * @throws Exception 
     */
    public void testLogStartup() throws Exception {
        // Read first line of file
        LOG.info("Note: This test assumes the signserver_audit.log was cleared before the appserver started");
        List<String> lines = readEntries(auditLogFile, 0, 1);
        final String line0 = lines.get(0);
        LOG.info(line0);
        assertTrue("Contains event", line0.contains("EVENT: SIGNSERVER_STARTUP"));
        assertTrue("Contains module", line0.contains("MODULE: SERVICE"));
        assertTrue("Contains version", line0.contains("VERSION: "));
    }
    
    // Not easily tested
    // public void testLogShutdown() throws Exception {
    //    fail("No implemented yet");
    // }
    
    public void testLogSetAndRemoveGlobalProperty() throws Exception {
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
        
        globalSession.reload();
    }
    
    public void testLogGlobalConfigReload() throws Exception {
        final int linesBefore = readEntriesCount(auditLogFile);
        
        // Test reload
        globalSession.reload();
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 1);
        String line = lines.get(0);
        LOG.info(line);
        assertTrue("Contains event", line.contains("EVENT: GLOBAL_CONFIG_RELOAD"));
        assertTrue("Contains module", line.contains("MODULE: GLOBAL_CONFIG"));
    }
    
    // Not easily tested
    // public void testLogGlobalConfigResync() throws Exception {
    //    fail("No implemented yet");
    // }
    
    public void testLogSetAndRemoveWorkerProperty() throws Exception {
        final int linesBefore = readEntriesCount(auditLogFile);
        
        // Test setProperty
        workerSession.setWorkerProperty(signerId, "TESTPROPERTY11", "TESTVALUE11");
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 1);
        String line = lines.get(0);
        LOG.info(line);
        assertTrue("Contains event", line.contains("EVENT: SET_WORKER_CONFIG"));
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        
        // Test removeProperty
        workerSession.removeWorkerProperty(signerId, "TESTPROPERTY11");
        lines = readEntries(auditLogFile, linesBefore + 1, 1);
        line = lines.get(0);
        LOG.info(line);
        
        assertTrue("Contains event", line.contains("EVENT: SET_WORKER_CONFIG"));
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
    }
    
    public void testLogCertInstalled() throws Exception {
        int linesBefore = readEntriesCount(auditLogFile);
        
        // Test with uploadSignerCertificate method (global scope)
        final X509Certificate cert = new JcaX509CertificateConverter().getCertificate(new CertBuilder().build());
        workerSession.uploadSignerCertificate(signerId, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        String line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: CERTINSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        assertTrue("Contains certificate", line.contains(new String(CertTools.getPEMFromCerts(Arrays.asList(cert)))));
        assertTrue("Contains scope", line.contains("SCOPE: GLOBAL"));
        
        // Test removeProperty
        workerSession.removeWorkerProperty(signerId, "SIGNERCERT");
        lines = readEntries(auditLogFile, linesBefore + 2, 2);
        LOG.info(lines);
        
        line = getTheLineContaining(lines, "EVENT: CERTINSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        assertTrue("Contains empty certificate", line.contains("CERTIFICATE: ;"));
        assertTrue("Contains scope", line.contains("SCOPE: GLOBAL"));
        
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        
        
        // Test with uploadSignerCertificate method (node scope)
        linesBefore = readEntriesCount(auditLogFile);
        workerSession.uploadSignerCertificate(signerId, cert.getEncoded(), GlobalConfiguration.SCOPE_NODE);
        
        lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: CERTINSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        assertTrue("Contains certificate", line.contains(new String(CertTools.getPEMFromCerts(Arrays.asList(cert)))));
        assertTrue("Contains scope", line.contains("SCOPE: NODE"));
        assertTrue("Contains node", line.contains("NODE: " + WorkerConfig.getNodeId()));
        
        // Remove the property
        workerSession.removeWorkerProperty(signerId, WorkerConfig.getNodeId() + ".SIGNERCERT");
        
        
        // Test when setting the property manually (global scope)
        linesBefore = readEntriesCount(auditLogFile);
        workerSession.setWorkerProperty(signerId, "SIGNERCERT", new String(CertTools.getPEMFromCerts(Arrays.asList(cert))));
        
        lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: CERTINSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        assertTrue("Contains certificate", line.contains(new String(CertTools.getPEMFromCerts(Arrays.asList(cert)))));
        assertTrue("Contains scope", line.contains("SCOPE: GLOBAL"));
        
        // Remove the property
        workerSession.removeWorkerProperty(signerId, "SIGNERCERT");
        
        
        // Test when setting the property manually (node scope)
        linesBefore = readEntriesCount(auditLogFile);
        workerSession.setWorkerProperty(signerId, "NODE47.SIGNERCERT", new String(CertTools.getPEMFromCerts(Arrays.asList(cert))));
        
        lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: CERTINSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        assertTrue("Contains certificate", line.contains(new String(CertTools.getPEMFromCerts(Arrays.asList(cert)))));
        assertTrue("Contains scope", line.contains("SCOPE: NODE"));
        assertTrue("Contains node", line.contains("NODE: NODE47"));
        
        // Remove the property
        workerSession.removeWorkerProperty(signerId, "NODE47.SIGNERCERT");
    }
    
    public void testLogCertChainInstalled() throws Exception {
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
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: CERTCHAININSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        assertTrue("Contains certificate", line.contains(new String(CertTools.getPEMFromCerts(Arrays.asList(cert, issuerCert)))));
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
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        assertTrue("Contains empty certificate chain", line.contains("CERTIFICATECHAIN: ;"));
        assertTrue("Contains scope", line.contains("SCOPE: GLOBAL"));
        
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        
        
        // Test with uploadSignerCertificateChain method (node scope)
        linesBefore = readEntriesCount(auditLogFile);
        workerSession.uploadSignerCertificateChain(signerId, Arrays.asList(cert.getEncoded(), issuerCert.getEncoded()), GlobalConfiguration.SCOPE_NODE);
        
        lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: CERTCHAININSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        assertTrue("Contains certificate", line.contains(new String(CertTools.getPEMFromCerts(Arrays.asList(cert, issuerCert)))));
        assertTrue("Contains scope", line.contains("SCOPE: NODE"));
        assertTrue("Contains node", line.contains("NODE: " + WorkerConfig.getNodeId()));
        
        // Remove the property
        workerSession.removeWorkerProperty(signerId, "SIGNERCERTCHAIN");
        
        
        // Test when setting the property manually (global scope)
        linesBefore = readEntriesCount(auditLogFile);
        workerSession.setWorkerProperty(signerId, "SIGNERCERTCHAIN", new String(CertTools.getPEMFromCerts(Arrays.asList(cert, issuerCert))));
        
        lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: CERTCHAININSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        assertTrue("Contains certificate", line.contains(new String(CertTools.getPEMFromCerts(Arrays.asList(cert, issuerCert)))));
        assertTrue("Contains scope", line.contains("SCOPE: GLOBAL"));
        
        // Remove the property
        if (!workerSession.removeWorkerProperty(signerId, "SIGNERCERTCHAIN")) {
            throw new Exception("Could not remove property");
        }
        
        
        // Test when setting the property manually (node scope)
        linesBefore = readEntriesCount(auditLogFile);
        workerSession.setWorkerProperty(signerId, "NODE47.SIGNERCERTCHAIN", new String(CertTools.getPEMFromCerts(Arrays.asList(cert, issuerCert))));
        
        lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: CERTCHAININSTALLED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        assertTrue("Contains certificate", line.contains(new String(CertTools.getPEMFromCerts(Arrays.asList(cert, issuerCert)))));
        assertTrue("Contains scope", line.contains("SCOPE: NODE"));
        assertTrue("Contains node", line.contains("NODE: NODE47"));
        
        // Remove the property
        workerSession.removeWorkerProperty(signerId, "NODE47.SIGNERCERTCHAIN");
    }
    
    public void testLogKeySelected() throws Exception {
        // Test when setting the property manually (global scope)
        int linesBefore = readEntriesCount(auditLogFile);
        workerSession.setWorkerProperty(signerId, "DEFAULTKEY", "ts_key00002");
        
        List<String> lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        String line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: KEYSELECTED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        assertTrue("Contains alias", line.contains("ALIAS: ts_key00002"));
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
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: KEYSELECTED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        assertTrue("Contains alias", line.contains("KEYALIAS: ;"));
        assertTrue("Contains scope", line.contains("SCOPE: GLOBAL"));
        
        
        // Test when setting the property manually (node scope)
        linesBefore = readEntriesCount(auditLogFile);
        workerSession.setWorkerProperty(signerId, "NODE47.DEFAULTKEY", "ts_key00003");
        
        lines = readEntries(auditLogFile, linesBefore, 2);
        LOG.info(lines);
        line = getTheLineContaining(lines, "EVENT: SET_WORKER_CONFIG");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
        
        line = getTheLineContaining(lines, "EVENT: KEYSELECTED");
        assertNotNull("Contains event", line);
        assertTrue("Contains module", line.contains("MODULE: WORKER_CONFIG"));
        assertTrue("Contains alias", line.contains("ALIAS: ts_key00003"));
        assertTrue("Contains scope", line.contains("SCOPE: NODE"));
        assertTrue("Contains node", line.contains("NODE: NODE47"));
        
        // Remove the property
        workerSession.removeWorkerProperty(signerId, "NODE47.DEFAULTKEY");
    }
    
    public void testLogKeyGenAndTestAndCSR() throws Exception {
        final String signerName = "TestKeyGenAndCSR1";
        final int signerId = 5980;
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
            
            // Add signer using the P12
            addP12DummySigner(signerId, signerName, p12, "foo123");
            
            // Test keygen
            int linesBefore = readEntriesCount(auditLogFile);
            workerSession.generateSignerKey(signerId, "RSA", "512", "ts_key00004", "foo123".toCharArray());

            List<String> lines = readEntries(auditLogFile, linesBefore, 1);
            LOG.info(lines);
            String line = lines.get(0);
            assertTrue("Contains event", line.contains("EVENT: KEYGEN"));
            assertTrue("Contains module", line.contains("MODULE: KEY_MANAGEMENT"));
            assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
            assertTrue("Contains alias", line.contains("KEYALIAS: ts_key00004"));
            assertTrue("Contains spec", line.contains("KEYSPEC: 512"));
            assertTrue("Contains alg", line.contains("KEYALG: RSA"));

            // Test keytest
            workerSession.activateSigner(signerId, "foo123");
            workerSession.testKey(signerId, "ts_key00004", "foo123".toCharArray());
            
            lines = readEntries(auditLogFile, linesBefore + 1, 1);
            LOG.info(lines);
            line = lines.get(0);
            assertTrue("Contains event", line.contains("EVENT: KEYTEST"));
            assertTrue("Contains module", line.contains("MODULE: KEY_MANAGEMENT"));
            assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
            assertTrue("Contains alias", line.contains("KEYALIAS: ts_key00004"));
            assertTrue("Contains test results", line.contains("KeyTestResult{alias=ts_key00004, success=true"));
            
            // Test gencsr
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=TS Signer 1,C=SE", null);
            ICertReqData req = workerSession.getCertificateRequest(signerId, certReqInfo, false);
            Base64SignerCertReqData reqData = (Base64SignerCertReqData) req;
            lines = readEntries(auditLogFile, linesBefore + 2, 1);
            LOG.info(lines);
            line = lines.get(0);
            assertTrue("Contains event", line.contains("EVENT: GENCSR"));
            assertTrue("Contains module", line.contains("MODULE: KEY_MANAGEMENT"));
            assertTrue("Contains worker id", line.contains("CUSTOM_ID: " + signerId));
            assertTrue("Contains csr", line.contains("CSR: " + new String(reqData.getBase64CertReq())));
        } finally {
            removeWorker(signerId);
        }
    }
    
    public void testLogSetStatusProperty() throws Exception {
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
    
    public void testLogProcessWorkerNotFound() throws Exception {
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
        assertTrue("Contains no correct worker id", line.contains("CUSTOM_ID: ;"));
        assertTrue("Contains log id", line.contains("LOG_ID: "));
        assertTrue("Contains success false", line.contains("PROCESS_SUCCESS: false"));
        assertTrue("Contains exception", line.contains("EXCEPTION: No such worker: 1234567"));
    }
    
    public void test99TearDownDatabase() throws Exception {
        removeWorker(signerId);
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
