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
import java.util.HashMap;
import java.util.Hashtable;
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
 * 
 */
public class TestMRTDSODSigner extends TestCase {

    private static IWorkerSession.IRemote sSSession = null;
    private static String signserverhome;
    private static int moduleVersion;

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

        sSSession.reloadConfiguration(7897);
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
        int reqid = 12;
        
        byte[] dataGroup1 = "Hello World".getBytes();
        byte[] dataGroup2 = "Hello World2".getBytes();
        
        MessageDigest d = MessageDigest.getInstance("SHA256", "BC");
        byte[] dataGroupHash1 = d.digest(dataGroup1);
        d.reset();
        byte[] dataGroupHash2 = d.digest(dataGroup2);
        d.reset();

        Map<Integer, byte[]> dataGroupHashes = new HashMap<Integer, byte[]>();   // Map of hashes, old joke =)
        dataGroupHashes.put(1, dataGroupHash1);
        dataGroupHashes.put(2, dataGroupHash2);


        SODSignResponse res = (SODSignResponse) sSSession.process(7897, new SODSignRequest(reqid, dataGroupHashes), new RequestContext());
        assertTrue(res != null);
        assertTrue(reqid == res.getRequestID());
        Certificate signercert = res.getSignerCertificate();
        assertNotNull(signercert);
        
        byte[] sodBytes = res.getProcessedData();
        SODFile sod = new SODFile(new ByteArrayInputStream(sodBytes));
        boolean verify = sod.checkDocSignature(signercert);
        assertTrue("Signature verification", verify);

        // TODO: Check the SOD

        // TODO: More tests and thing through if this test is ok

    }

    /*
     * Test method for 'org.signserver.server.MRTDSigner.getStatus()'
     */
    public void test03GetStatus() throws Exception {
        SignerStatus stat = (SignerStatus) sSSession.getStatus(7897);
        assertTrue(stat.getTokenStatus() == SignerStatus.STATUS_ACTIVE);

    }

    

    public void test99TearDownDatabase() throws Exception {
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker", "7897"});

        TestUtils.assertSuccessfulExecution(new String[]{"module", "remove", "MRTDSIGNER", "" + moduleVersion});
        sSSession.reloadConfiguration(7897);
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
