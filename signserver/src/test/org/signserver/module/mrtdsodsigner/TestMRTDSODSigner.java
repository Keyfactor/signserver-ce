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
import java.io.File;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
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
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.RequestContext;
import org.signserver.common.SODSignRequest;
import org.signserver.common.SODSignResponse;
import org.signserver.common.SignServerConstants;
import org.signserver.common.SignServerUtil;
import org.signserver.common.SignerStatus;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.cryptotokens.HardCodedCryptoToken;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Tests the MRTDSODSigner.
 *
 * @version $Id$
 */
public class TestMRTDSODSigner extends TestCase {
	
    /** Worker7897: Default algorithms, default hashing setting */
    private static final int WORKER1 = 7897;

    /** Worker7898: SHA512, default hashing setting */
    private static final int WORKER2 = 7898;

    /** Worker7899: Default algorithms, DODATAGROUPHASHING=true */
    private static final int WORKER3 = 7899;

    /** Worker7900: SHA512, DODATAGROUPHASHING=true */
    private static final int WORKER4 = 7900;

    /** Worker7901: Same as WORKER1 but with P12CryptoToken. */
    private static final int WORKER1B = 7901;

    private static final int WORKER1C = 7902;
    
    private static final int WORKER1D = 7903;

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

        // WORKER1B uses a P12 keystore
        sSSession.setWorkerProperty(WORKER1B, "KEYSTOREPATH", signserverhome
                + File.separator + "src" + File.separator + "test"
                + File.separator + "pdfsigner.p12");
        sSSession.setWorkerProperty(WORKER1B, "KEYSTOREPASSWORD", "foo123");

//                signserverhome
//                + File.separator + "src" + File.separator + "test"
//                + File.separator + "pdfsigner.p12");
        sSSession.setWorkerProperty(WORKER1B, "KEYSTOREPASSWORD", "foo123");

        sSSession.reloadConfiguration(WORKER1);
        sSSession.reloadConfiguration(WORKER2);
        sSSession.reloadConfiguration(WORKER3);
        sSSession.reloadConfiguration(WORKER4);
        sSSession.reloadConfiguration(WORKER1B);
        sSSession.reloadConfiguration(WORKER1C);
        sSSession.reloadConfiguration(WORKER1D);
    }

    /**
     * Creates and verifies a simple SODFile
     * @throws Exception
     */
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
     * Requests signing of some data group hashes, using two different signers
     * with different algorithms and verifies the result.
     * @throws Exception
     */
    public void test02SignData() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));
        signHelper(WORKER1, 12, dataGroups1, false, "SHA256", "SHA256withRSA");

        // DG3, DG7, DG8, DG13 and default values
        Map<Integer, byte[]> dataGroups2 = new LinkedHashMap<Integer, byte[]>();
        dataGroups2.put(3, digestHelper("Dummy Value 3".getBytes(), "SHA256"));
        dataGroups2.put(7, digestHelper("Dummy Value 4".getBytes(), "SHA256"));
        dataGroups2.put(8, digestHelper("Dummy Value 5".getBytes(), "SHA256"));
        dataGroups2.put(13, digestHelper("Dummy Value 6".getBytes(), "SHA256"));
        signHelper(WORKER1, 13, dataGroups2, false, "SHA256", "SHA256withRSA");

        // DG1, DG2 with the other worker which uses SHA512 and SHA512withRSA
        Map<Integer, byte[]> dataGroups3 = new LinkedHashMap<Integer, byte[]>();
        dataGroups3.put(1, digestHelper("Dummy Value 7".getBytes(), "SHA512"));
        dataGroups3.put(2, digestHelper("Dummy Value 8".getBytes(), "SHA512"));
        signHelper(WORKER2, 14, dataGroups3, false, "SHA512", "SHA512withRSA");
    }

    /**
     * Requests signing of some data groups, using two different signers
     * with different algorithms and verifies the result. The signer does the
     * hashing.
     * @throws Exception
     */
    public void test03SignUnhashedData() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, "Dummy Value 1".getBytes());
        dataGroups1.put(2, "Dummy Value 2".getBytes());
        signHelper(WORKER3, 15, dataGroups1, true, "SHA256", "SHA256withRSA");

        // DG3, DG7, DG8, DG13 and default values
        Map<Integer, byte[]> dataGroups2 = new LinkedHashMap<Integer, byte[]>();
        dataGroups2.put(3, "Dummy Value 3".getBytes());
        dataGroups2.put(7, "Dummy Value 4".getBytes());
        dataGroups2.put(8, "Dummy Value 5".getBytes());
        dataGroups2.put(13, "Dummy Value 6".getBytes());
        signHelper(WORKER3, 16, dataGroups2, true, "SHA256", "SHA256withRSA");

        // DG1, DG2 with the other worker which uses SHA512 and SHA512withRSA
        Map<Integer, byte[]> dataGroups3 = new LinkedHashMap<Integer, byte[]>();
        dataGroups3.put(1, "Dummy Value 7".getBytes());
        dataGroups3.put(2, "Dummy Value 8".getBytes());
        signHelper(WORKER4, 17, dataGroups3, true, "SHA512", "SHA512withRSA");
    }

    public void test04MinRemainingCertVValidity() throws Exception {

    	// A signing operation that will work
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));
        signHelper(WORKER1, 12, dataGroups1, false, "SHA256", "SHA256withRSA");

        // Set property to limit remaining cert validity
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(HardCodedCryptoToken.certbytes));			

        sSSession.uploadSignerCertificate(WORKER1, cert, GlobalConfiguration.SCOPE_GLOBAL);
        sSSession.setWorkerProperty(WORKER1, SignServerConstants.MINREMAININGCERTVALIDITY, "6300");
        sSSession.reloadConfiguration(WORKER1);
    	// Signing operation should not work now
        boolean thrown = false;
        try {
            signHelper(WORKER1, 12, dataGroups1, false, "SHA256", "SHA256withRSA");        	
        } catch (CryptoTokenOfflineException e) {
        	thrown = true;
        }
        assertTrue(thrown);
    }

        public void test04bMinRemainingCertVValidityWithSoftKeystore()
                throws Exception {

    	// A signing operation that will work
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));
        signHelper(WORKER1B, 12, dataGroups1, false, "SHA256", "SHA256withRSA");

        // Set property to limit remaining cert validity
        sSSession.setWorkerProperty(WORKER1B,
                SignServerConstants.MINREMAININGCERTVALIDITY, "6300");
        sSSession.reloadConfiguration(WORKER1B);
    	// Signing operation should not work now
        boolean thrown = false;
        try {
            signHelper(WORKER1B, 12, dataGroups1, false, "SHA256",
                    "SHA256withRSA");
        } catch (CryptoTokenOfflineException e) {
        	thrown = true;
        }
        assertTrue(thrown);
    }

    /**
     * Tests all validities: certificate, privatekey and min remaining period.
     * @throws Exception in case of error.
     */
    public void test04cRemainingValidity() throws Exception {

        Calendar cal = Calendar.getInstance();

        sSSession.setWorkerProperty(WORKER1C, "CHECKCERTVALIDITY", "True");
        sSSession.setWorkerProperty(WORKER1C, "CHECKCERTPRIVATEKEYVALIDITY",
                "False");
        sSSession.setWorkerProperty(WORKER1C, "MINREMAININGCERTVALIDITY", "0");

        //    Certificate with: cert#1: priv=[2015, 2020], cert=[2025, 2030]
        //              cert#2: priv=[2025, 2030], cert=[2015, 2020]
        //
        //
        //    test#1: 	getSignerValidityNotAfter:  cert#1, bCert 	= 2030
        Date d = sSSession.getSigningValidityNotAfter(WORKER1C);
        assertNotNull("test#1 not null", d);
        cal.setTime(d);
        assertEquals(2030, cal.get(Calendar.YEAR));

        //    test#2	getSignerValidityNotBefore: cert#1, bCert       = 2025
        d = sSSession.getSigningValidityNotBefore(WORKER1C);
        assertNotNull("test#2 not null", d);
        cal.setTime(d);
        assertEquals(2025, cal.get(Calendar.YEAR));

        //    test#3: 	getSignerValidityNotAfter:  cert#1, bPriv       = 2020
        sSSession.setWorkerProperty(WORKER1C, "CHECKCERTVALIDITY", "False");
        sSSession.setWorkerProperty(WORKER1C, "CHECKCERTPRIVATEKEYVALIDITY",
                "True");
        d = sSSession.getSigningValidityNotAfter(WORKER1C);
        assertNotNull("test#3 not null", d);
        cal.setTime(d);
        assertEquals(2020, cal.get(Calendar.YEAR));

        //    test#4	getSignerValidityNotBefore: cert#1, bPriv       = 2015
        d = sSSession.getSigningValidityNotBefore(WORKER1C);
        assertNotNull("test#4 not null", d);
        cal.setTime(d);
        assertEquals(2015, cal.get(Calendar.YEAR));

        //    test#5: 	getSignerValidityNotAfter:  cert#1, bCert, bPriv	  = 2020
        sSSession.setWorkerProperty(WORKER1C, "CHECKCERTVALIDITY", "True");
        d = sSSession.getSigningValidityNotAfter(WORKER1C);
        assertNotNull("test#5 not null", d);
        cal.setTime(d);
        assertEquals(2020, cal.get(Calendar.YEAR));

        //    test#6		getSignerValidityNotBefore: cert#1, bCert, bPrive = 2015
        d = sSSession.getSigningValidityNotBefore(WORKER1C);
        assertNotNull("test#6 not null", d);
        cal.setTime(d);
        assertEquals(2015, cal.get(Calendar.YEAR));

        //    test#7: 	getSignerValidityNotAfter:  cert#1, bCert, r10 		  = 2020
        sSSession.setWorkerProperty(WORKER1C, "CHECKCERTPRIVATEKEYVALIDITY",
                "False");
        sSSession.setWorkerProperty(WORKER1C, "MINREMAININGCERTVALIDITY", "3650");
        d = sSSession.getSigningValidityNotAfter(WORKER1C);
        assertNotNull("test#7 not null", d);
        cal.setTime(d);
        assertEquals(2020, cal.get(Calendar.YEAR));

        //    test#8		getSignerValidityNotBefore: cert#1, bCert, r10	  = 2015
        d = sSSession.getSigningValidityNotBefore(WORKER1C);
        assertNotNull("test#8 not null", d);
        cal.setTime(d);
        assertEquals(2025, cal.get(Calendar.YEAR));

        //    test#9: 	getSignerValidityNotAfter:  cert#1, bCert, r4 		  = 2026
        sSSession.setWorkerProperty(WORKER1C, "MINREMAININGCERTVALIDITY", "1460");
        d = sSSession.getSigningValidityNotAfter(WORKER1C);
        assertNotNull("test#9 not null", d);
        cal.setTime(d);
        assertEquals(2026, cal.get(Calendar.YEAR));

        //    test#10:	getSignerValidityNotBefore: cert#1, bCert, r4		  = 2025
        d = sSSession.getSigningValidityNotBefore(WORKER1C);
        assertNotNull("test#10 not null", d);
        cal.setTime(d);
        assertEquals(2025, cal.get(Calendar.YEAR));

        //    test#21: 	getSignerValidityNotAfter:  cert#2, bCert 		  = 2020
        sSSession.setWorkerProperty(WORKER1D, "CHECKCERTVALIDITY", "True");
        sSSession.setWorkerProperty(WORKER1D, "CHECKCERTPRIVATEKEYVALIDITY",
                "False");
        sSSession.setWorkerProperty(WORKER1D, "MINREMAININGCERTVALIDITY", "0");
        d = sSSession.getSigningValidityNotAfter(WORKER1D);
        assertNotNull("test#21 not null", d);
        cal.setTime(d);
        assertEquals(2020, cal.get(Calendar.YEAR));

        //    test#22		getSignerValidityNotBefore: cert#2, bCert	  = 2015
        assertNotNull("test#22 not null", d);
        d = sSSession.getSigningValidityNotBefore(WORKER1D);
        cal.setTime(d);
        assertEquals(2015, cal.get(Calendar.YEAR));

        //    test#23: 	getSignerValidityNotAfter:  cert#2, bPriv 		  = 2030
        sSSession.setWorkerProperty(WORKER1D, "CHECKCERTVALIDITY", "False");
        sSSession.setWorkerProperty(WORKER1D, "CHECKCERTPRIVATEKEYVALIDITY",
                "True");
        d = sSSession.getSigningValidityNotAfter(WORKER1D);
        assertNotNull("test#23 not null", d);
        cal.setTime(d);
        assertEquals(2030, cal.get(Calendar.YEAR));

        //    test#24		getSignerValidityNotBefore: cert#2, bPriv	 = 2025
        d = sSSession.getSigningValidityNotBefore(WORKER1D);
        assertNotNull("test#24 not null", d);
        cal.setTime(d);
        assertEquals(2025, cal.get(Calendar.YEAR));

        //    test#25: 	getSignerValidityNotAfter:  cert#2, bCert, bPriv	 = 2020
        sSSession.setWorkerProperty(WORKER1D, "CHECKCERTVALIDITY", "True");
        d = sSSession.getSigningValidityNotAfter(WORKER1D);
        assertNotNull("test#25 not null", d);
        cal.setTime(d);
        assertEquals(2020, cal.get(Calendar.YEAR));

        //    test#26		getSignerValidityNotBefore: cert#2, bCert, bPriv = 2025
        d = sSSession.getSigningValidityNotBefore(WORKER1D);
        assertNotNull("test#26 not null", d);
        cal.setTime(d);
        assertEquals(2025, cal.get(Calendar.YEAR));

        //    test#27: 	getSignerValidityNotAfter:  cert#2, bCert, r10 		  = 2010 r10 -> 3650
        sSSession.setWorkerProperty(WORKER1D, "CHECKCERTPRIVATEKEYVALIDITY",
                "False");
        sSSession.setWorkerProperty(WORKER1D, "MINREMAININGCERTVALIDITY", "3650");
        d = sSSession.getSigningValidityNotAfter(WORKER1D);
        assertNotNull("test#27 not null", d);
        cal.setTime(d);
        assertEquals(2010, cal.get(Calendar.YEAR));

        //    test#28		getSignerValidityNotBefore: cert#2, bCert, r10	  = 2015
        d = sSSession.getSigningValidityNotBefore(WORKER1D);
        assertNotNull("test#28 not null", d);
        cal.setTime(d);
        assertEquals(2015, cal.get(Calendar.YEAR));

        //    test#29: 	getSignerValidityNotAfter:  cert#2, bCert, r4 		  = 2016 r4 -> 1460
        sSSession.setWorkerProperty(WORKER1D, "MINREMAININGCERTVALIDITY", "1460");
        d = sSSession.getSigningValidityNotAfter(WORKER1D);
        assertNotNull("test#29 not null", d);
        cal.setTime(d);
        assertEquals(2016, cal.get(Calendar.YEAR));

        //    test#30:	getSignerValidityNotBefore: cert#2, bCert, r4		  = 2015
        d = sSSession.getSigningValidityNotBefore(WORKER1D);
        assertNotNull("test#30 not null", d);
        cal.setTime(d);
        assertEquals(2015, cal.get(Calendar.YEAR));
    }

    private void signHelper(int workerId, int requestId, Map<Integer, byte[]> dataGroups, boolean signerDoesHashing, String digestAlg, String sigAlg) throws Exception {

        // Create expected hashes
    	Map<Integer, byte[]> expectedHashes;
    	if(signerDoesHashing) {
            MessageDigest d = MessageDigest.getInstance(digestAlg, "BC");
            expectedHashes = new HashMap<Integer, byte[]>();
            for(Map.Entry<Integer, byte[]> entry : dataGroups.entrySet()) {
                expectedHashes.put(entry.getKey(), d.digest(entry.getValue()));
                d.reset();
            }
    	} else {
            expectedHashes = dataGroups;
    	}
    	
        SODSignResponse res = (SODSignResponse) sSSession.process(workerId, new SODSignRequest(requestId, dataGroups), new RequestContext());
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
        assertEquals(expectedHashes.size(), actualDataGroupHashes.size());
        for(Map.Entry<Integer, byte[]> entry : actualDataGroupHashes.entrySet()) {
            assertTrue("DG"+entry.getKey(), Arrays.equals(expectedHashes.get(entry.getKey()), entry.getValue()));
        }
        assertEquals(digestAlg, sod.getDigestAlgorithm());
        assertEquals(sigAlg, sod.getDigestEncryptionAlgorithm());
    }

    private byte[] digestHelper(byte[] data, String digestAlgorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(digestAlgorithm);
        return md.digest(data);
    }
    
    /**
     * Test method for 'org.signserver.server.MRTDSigner.getStatus()'
     */
    public void test05GetStatus() throws Exception {
        SignerStatus stat = (SignerStatus) sSSession.getStatus(7897);
        assertTrue(stat.getTokenStatus() == SignerStatus.STATUS_ACTIVE);
    }
    

    public void test99TearDownDatabase() throws Exception {
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker", ""+WORKER1});
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker", ""+WORKER2});
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker", ""+WORKER3});
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker", ""+WORKER4});
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker", ""+WORKER1B});
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker", ""+WORKER1C});
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker", ""+WORKER1D});
        TestUtils.assertSuccessfulExecution(new String[]{"module", "remove", "MRTDSODSIGNER", "" + moduleVersion});
        sSSession.reloadConfiguration(WORKER1);
        sSSession.reloadConfiguration(WORKER2);
        sSSession.reloadConfiguration(WORKER3);
        sSSession.reloadConfiguration(WORKER4);
        sSSession.reloadConfiguration(WORKER1B);
        sSSession.reloadConfiguration(WORKER1C);
        sSSession.reloadConfiguration(WORKER1D);
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
