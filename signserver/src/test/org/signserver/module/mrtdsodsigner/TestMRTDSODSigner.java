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
package org.signserver.module.mrtdsodsigner;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.naming.Context;
import javax.naming.InitialContext;

import junit.framework.TestCase;

import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;
import org.jmrtd.SODFile;
import org.signserver.cli.CommonAdminInterface;
import org.signserver.common.RequestContext;
import org.signserver.common.SODSignRequest;
import org.signserver.common.SODSignResponse;
import org.signserver.common.SignServerUtil;
import org.signserver.common.SignerStatus;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/**
 * @version $Id$
 */
public class TestMRTDSODSigner extends TestCase {

    /** Worker with no DIGESTALGORITHM or DIGESTALGORITHM property set */
    private static final int WORKER1 = 7897;

    /** Worker with DIGESTALGORITHM and DIGESTALGORITHM specified */
    private static final int WORKER2 = 7898;

    private static IWorkerSession.IRemote sSSession = null;
    private static String signserverhome;
    private static int moduleVersion;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
        Context context = getInitialContext();
        sSSession = (IWorkerSession.IRemote) context.lookup(IWorkerSession.IRemote.JNDI_NAME);
        TestUtils.redirectToTempOut();
        TestUtils.redirectToTempErr();
        TestingSecurityManager.install();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
        CommonAdminInterface.BUILDMODE = "SIGNSERVER";
    }

    /* (non-Javadoc)
     * @see junit.framework.TestCase#tearDown()
     */
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        TestingSecurityManager.remove();
    }

    public void test00SetupDatabase() throws Exception {

        MARFileParser marFileParser = new MARFileParser(signserverhome + "/dist-server/mrtdsodsigner.mar");
        moduleVersion = marFileParser.getVersionFromMARFile();

        TestUtils.assertSuccessfulExecution(new String[]{"module", "add",
                    signserverhome + "/dist-server/mrtdsodsigner.mar", "junittest"});
        assertTrue(TestUtils.grepTempOut("Loading module MRTDSODSIGNER"));
        assertTrue(TestUtils.grepTempOut("Module loaded successfully."));

        sSSession.reloadConfiguration(WORKER1);
        sSSession.reloadConfiguration(WORKER2);
    }

    public void test01SODFile() throws Exception {
    	Map<Integer, byte[]> dataGroupHashes = new HashMap<Integer, byte[]>();
    	dataGroupHashes.put(Integer.valueOf(1), "12345".getBytes());
    	dataGroupHashes.put(Integer.valueOf(4), "abcdef".getBytes());
    	
    	KeyPair keys = KeyTools.genKeys("1024", "RSA");
    	X509Certificate cert = CertTools.genSelfCert("CN=mrtdsodtest", 33, null, keys.getPrivate(), keys.getPublic(), "SHA256WithRSA", false); 
        SODFile sod = new SODFile("SHA256", "SHA256withRSA", dataGroupHashes, keys.getPrivate(), cert);
        assertNotNull(sod);
        boolean verify = sod.checkDocSignature(cert);
        assertTrue(verify);
        byte[] encoded = sod.getEncoded();
        SODFile sod2 = new SODFile(new ByteArrayInputStream(encoded));
        verify = sod2.checkDocSignature(cert);
        assertTrue(verify);
    }

    /**
     * Test method for 'org.signserver.server.MRTDSigner.signData(ISignRequest)'
     */
    public void test02SignData() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, "Dummy Value 1".getBytes());
        dataGroups1.put(2, "Dummy Value 2".getBytes());
        signHelper(WORKER1, 12, dataGroups1, "SHA256", "SHA256withRSA");

        // DG3, DG7, DG8, DG13 and default values
        Map<Integer, byte[]> dataGroups2 = new LinkedHashMap<Integer, byte[]>();
        dataGroups2.put(3, "Dummy Value 3".getBytes());
        dataGroups2.put(7, "Dummy Value 4".getBytes());
        dataGroups2.put(8, "Dummy Value 5".getBytes());
        dataGroups2.put(13, "Dummy Value 6".getBytes());
        signHelper(WORKER1, 13, dataGroups2, "SHA256", "SHA256withRSA");

        // DG1, DG2 with the other worker which uses SHA512 and SHA512withRSA
        Map<Integer, byte[]> dataGroups3 = new LinkedHashMap<Integer, byte[]>();
        dataGroups3.put(1, "Dummy Value 7".getBytes());
        dataGroups3.put(2, "Dummy Value 8".getBytes());
        signHelper(WORKER2, 14, dataGroups3, "SHA512", "SHA512withRSA");

    }

    private void signHelper(int workerId, int requestId, Map<Integer, byte[]> dataGroups, String digestAlg, String sigAlg) throws Exception {

        // Create a map with the hashes to
        MessageDigest d = MessageDigest.getInstance(digestAlg, "BC");
        Map<Integer, byte[]> dataGroupHashes = new HashMap<Integer, byte[]>();
        for(Map.Entry<Integer, byte[]> entry : dataGroups.entrySet()) {
            dataGroupHashes.put(entry.getKey(), d.digest(entry.getValue()));
            d.reset();
        }

        SODSignResponse res = (SODSignResponse) sSSession.process(workerId, new SODSignRequest(requestId, dataGroupHashes), new RequestContext());
        assertNotNull(res);
        assertEquals(requestId, res.getRequestID());
        Certificate signercert = res.getSignerCertificate();
        assertNotNull(signercert);

        byte[] sodBytes = res.getProcessedData();
        SODFile sod = new SODFile(new ByteArrayInputStream(sodBytes));
        boolean verify = sod.checkDocSignature(signercert);
        assertTrue("Signature verification", verify);

        // Check the SOD
        Map<Integer, byte[]> actualDataGroupHashes = sod.getDataGroupHashes();
        assertEquals(dataGroupHashes.size(), actualDataGroupHashes.size());
        for(Map.Entry<Integer, byte[]> entry : actualDataGroupHashes.entrySet()) {
            assertTrue("DG"+entry.getKey(), Arrays.equals(dataGroupHashes.get(entry.getKey()), entry.getValue()));
        }
        assertEquals(digestAlg, sod.getDigestAlgorithm());
        assertEquals(sigAlg, sod.getDigestEncryptionAlgorithm());
    }

    /*
     * Test method for 'org.signserver.server.MRTDSigner.getStatus()'
     */
    public void test03GetStatus() throws Exception {
        SignerStatus stat = (SignerStatus) sSSession.getStatus(7897);
        assertTrue(stat.getTokenStatus() == SignerStatus.STATUS_ACTIVE);

    }

    

    public void test99TearDownDatabase() throws Exception {
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker", ""+WORKER1});
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker", ""+WORKER2});

        TestUtils.assertSuccessfulExecution(new String[]{"module", "remove", "MRTDSIGNER", "" + moduleVersion});
        sSSession.reloadConfiguration(WORKER1);
        sSSession.reloadConfiguration(WORKER2);
    }

    /**
     * Get the initial naming context
     */
    protected Context getInitialContext() throws Exception {
        Hashtable<String, String> props = new Hashtable<String, String>();
        props.put(Context.INITIAL_CONTEXT_FACTORY, "org.jnp.interfaces.NamingContextFactory");
        props.put( Context.URL_PKG_PREFIXES, "org.jboss.naming:org.jnp.interfaces");
        props.put(Context.PROVIDER_URL, "jnp://localhost:1099");
        Context ctx = new InitialContext(props);
        return ctx;
    }
}
