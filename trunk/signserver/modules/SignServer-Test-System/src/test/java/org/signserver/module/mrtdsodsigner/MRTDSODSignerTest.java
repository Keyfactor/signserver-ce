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
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.junit.After;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.cli.CommandLineInterface;
import org.signserver.common.*;
import org.signserver.module.mrtdsodsigner.jmrtd.SODFile;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestingSecurityManager;
import org.junit.Before;
import org.junit.Test;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.test.utils.TestCerts;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.test.utils.builders.CryptoUtils;

/**
 * Tests the MRTDSODSigner.
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MRTDSODSignerTest extends ModulesTestCase {

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
    
    /** Worker7904: SHA256WithECDSA, DODATAGROUPHASHING=true */
    private static final int WORKER5 = 7904;

    private static final String ALIAS_DEMODSEC = "MRTD Sod Signer";
    private static final String ALIAS_DEMODS1 = "sod00001";

    private final WorkerSession workerSession = getWorkerSession();
    private final ProcessSessionRemote processSession = getProcessSession();
    
    @Before
    @Override
    protected void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    /* (non-Javadoc)
     * @see junit.framework.TestCase#tearDown()
     */
    @After
    @Override
    protected void tearDown() throws Exception {
        TestingSecurityManager.remove();
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        assertEquals(CommandLineInterface.RETURN_SUCCESS, 
                getAdminCLI().execute("setproperties", getSignServerHome().getAbsolutePath() + "/res/test/test-mrtdsodsigner-configuration.properties"));

        // WORKER1 uses a P12 keystore
        workerSession.setWorkerProperty(WORKER1, "KEYSTOREPATH",
                getSignServerHome().getAbsolutePath()
                + File.separator + "res" + File.separator + "test"
                + File.separator + "dss10" + File.separator + "dss10_keystore.p12");
        workerSession.setWorkerProperty(WORKER1, "KEYSTOREPASSWORD", "foo123");
        workerSession.setWorkerProperty(WORKER1, "DEFAULTKEY", ALIAS_DEMODS1);

        // WORKER1B uses a P12 keystore
        workerSession.setWorkerProperty(WORKER1B, "KEYSTOREPATH",
                getSignServerHome().getAbsolutePath()
                + File.separator + "res" + File.separator + "test"
                + File.separator + "dss10/dss10_signer1.p12");
        workerSession.setWorkerProperty(WORKER1B, "KEYSTOREPASSWORD", "foo123");
        workerSession.setWorkerProperty(WORKER1B, "DEFAULTKEY", "Signer 1");

        // WORKER2 uses a P12 keystore
        workerSession.setWorkerProperty(WORKER2, "KEYSTOREPATH",
                getSignServerHome().getAbsolutePath()
                + File.separator + "res" + File.separator + "test"
                + File.separator + "dss10" + File.separator + "dss10_keystore.p12");
        workerSession.setWorkerProperty(WORKER2, "KEYSTOREPASSWORD", "foo123");
        workerSession.setWorkerProperty(WORKER2, "DEFAULTKEY", ALIAS_DEMODS1);

        // WORKER3 uses a P12 keystore
        workerSession.setWorkerProperty(WORKER3, "KEYSTOREPATH",
                getSignServerHome().getAbsolutePath()
                + File.separator + "res" + File.separator + "test"
                + File.separator + "dss10" + File.separator + "dss10_keystore.p12");
        workerSession.setWorkerProperty(WORKER3, "KEYSTOREPASSWORD", "foo123");
        workerSession.setWorkerProperty(WORKER3, "DEFAULTKEY", ALIAS_DEMODS1);

        // WORKER4 uses a P12 keystore
        workerSession.setWorkerProperty(WORKER4, "KEYSTOREPATH",
                getSignServerHome().getAbsolutePath()
                + File.separator + "res" + File.separator + "test"
                + File.separator + "dss10" + File.separator + "dss10_keystore.p12");
        workerSession.setWorkerProperty(WORKER4, "KEYSTOREPASSWORD", "foo123");
        workerSession.setWorkerProperty(WORKER4, "DEFAULTKEY", ALIAS_DEMODS1);

        // WORKER5 uses a P12 keystore and ECC
        workerSession.setWorkerProperty(WORKER5, "KEYSTOREPATH",
                getSignServerHome().getAbsolutePath()
                + File.separator + "res" + File.separator + "test"
                + File.separator + "demodsecc1.p12");
        workerSession.setWorkerProperty(WORKER5, "KEYSTOREPASSWORD", "foo123");
        workerSession.setWorkerProperty(WORKER5, "DEFAULTKEY", ALIAS_DEMODSEC);

        workerSession.reloadConfiguration(WORKER1);
        workerSession.reloadConfiguration(WORKER2);
        workerSession.reloadConfiguration(WORKER3);
        workerSession.reloadConfiguration(WORKER4);
        workerSession.reloadConfiguration(WORKER5);
        workerSession.reloadConfiguration(WORKER1B);

        addSigner("org.signserver.module.mrtdsodsigner.MRTDSODSigner", WORKER1C, "TestMRTDSODSigner1c", true);
        workerSession.setWorkerProperty(WORKER1C, "SIGNERCERT", TestCerts.SIGNER1C_CERT);
        workerSession.setWorkerProperty(WORKER1C, "SIGNERCERTCHAIN", TestCerts.SIGNER1C_CERT);
        workerSession.reloadConfiguration(WORKER1C);
        addSigner("org.signserver.module.mrtdsodsigner.MRTDSODSigner", WORKER1D, "TestMRTDSODSigner1d", true);
        workerSession.setWorkerProperty(WORKER1D, "SIGNERCERT", TestCerts.SIGNER1D_CERT);
        workerSession.setWorkerProperty(WORKER1D, "SIGNERCERTCHAIN", TestCerts.SIGNER1D_CERT);
        workerSession.reloadConfiguration(WORKER1D);
    }

    /**
     * Requests signing of some data group hashes, using two different signers
     * with different algorithms and verifies the result.
     * @throws Exception
     */
    @Test
    public void test02SignData() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));
        signHelper(WORKER1, 12, dataGroups1, false, "SHA256", "SHA256withRSA");

        // DG3, DG7, DG8, DG13 and default values
        Map<Integer, byte[]> dataGroups2 = new LinkedHashMap<>();
        dataGroups2.put(3, digestHelper("Dummy Value 3".getBytes(), "SHA256"));
        dataGroups2.put(7, digestHelper("Dummy Value 4".getBytes(), "SHA256"));
        dataGroups2.put(8, digestHelper("Dummy Value 5".getBytes(), "SHA256"));
        dataGroups2.put(13, digestHelper("Dummy Value 6".getBytes(), "SHA256"));
        signHelper(WORKER1, 13, dataGroups2, false, "SHA256", "SHA256withRSA");

        // DG1, DG2 with the other worker which uses SHA512 and SHA512withRSA
        Map<Integer, byte[]> dataGroups3 = new LinkedHashMap<>();
        dataGroups3.put(1, digestHelper("Dummy Value 7".getBytes(), "SHA512"));
        dataGroups3.put(2, digestHelper("Dummy Value 8".getBytes(), "SHA512"));
        signHelper(WORKER2, 14, dataGroups3, false, "SHA512", "SHA512withRSA");

        // DG1, DG2 with the other worker which uses SHA256 and SHA256withECDSA
        signHelper(WORKER5, 15, dataGroups2, false, "SHA256", "SHA256withECDSA");
    }

    /**
     * Requests signing of some data groups, using two different signers
     * with different algorithms and verifies the result. The signer does the
     * hashing.
     * @throws Exception
     */
    @Test
    public void test03SignUnhashedData() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<>();
        dataGroups1.put(1, "Dummy Value 1".getBytes());
        dataGroups1.put(2, "Dummy Value 2".getBytes());
        signHelper(WORKER3, 15, dataGroups1, true, "SHA256", "SHA256withRSA");

        // DG3, DG7, DG8, DG13 and default values
        Map<Integer, byte[]> dataGroups2 = new LinkedHashMap<>();
        dataGroups2.put(3, "Dummy Value 3".getBytes());
        dataGroups2.put(7, "Dummy Value 4".getBytes());
        dataGroups2.put(8, "Dummy Value 5".getBytes());
        dataGroups2.put(13, "Dummy Value 6".getBytes());
        signHelper(WORKER3, 16, dataGroups2, true, "SHA256", "SHA256withRSA");

        // DG1, DG2 with the other worker which uses SHA512 and SHA512withRSA
        Map<Integer, byte[]> dataGroups3 = new LinkedHashMap<>();
        dataGroups3.put(1, "Dummy Value 7".getBytes());
        dataGroups3.put(2, "Dummy Value 8".getBytes());
        signHelper(WORKER4, 17, dataGroups3, true, "SHA512", "SHA512withRSA");
    }

    @Test
    public void test04MinRemainingCertVValidity() throws Exception {
        // A signing operation that will work
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));
        signHelper(WORKER1, 12, dataGroups1, false, "SHA256", "SHA256withRSA");

        // Set property to limit remaining cert validity
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Test validity cert", null);
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER1), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cscaCert = new JcaX509v3CertificateBuilder(new X500Name("CN=Test validity CSCA"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), new X500Name("CN=Test validity CSCA"), issuerKeyPair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));
        
        X509CertificateHolder cert = new X509v3CertificateBuilder(cscaCert.getSubject(), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo())
                .build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        workerSession.uploadSignerCertificate(WORKER1, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(WORKER1, Arrays.asList(cert.getEncoded(), cscaCert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.setWorkerProperty(WORKER1, SignServerConstants.MINREMAININGCERTVALIDITY, "6300");
        workerSession.reloadConfiguration(WORKER1);
        // Signing operation should not work now
        boolean thrown = false;
        try {
            signHelper(WORKER1, 12, dataGroups1, false, "SHA256", "SHA256withRSA");
        } catch (CryptoTokenOfflineException e) {
            thrown = true;
        }
        assertTrue(thrown);
        
        // Test that there is an error as the signer is not valid yet
        WorkerStatus status = workerSession.getStatus(new WorkerIdentifier(WORKER1));
        String errors = status.getFatalErrors().toString();
        assertTrue(errors, errors.contains("xpired"));
    }

    @Test
    public void test04bMinRemainingCertVValidityWithSoftKeystore()
            throws Exception {
        // A signing operation that will work
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));
        signHelper(WORKER1B, 12, dataGroups1, false, "SHA256", "SHA256withRSA");

        // Set property to limit remaining cert validity
        workerSession.setWorkerProperty(WORKER1B,
                SignServerConstants.MINREMAININGCERTVALIDITY, "6300");
        workerSession.reloadConfiguration(WORKER1B);
        
        System.out.println("remaining: " + workerSession.getSigningValidityNotAfter(new WorkerIdentifier(WORKER1B)));
        
        // Signing operation should not work now
        boolean thrown = false;
        try {
            signHelper(WORKER1B, 12, dataGroups1, false, "SHA256",
                    "SHA256withRSA");
        } catch (CryptoTokenOfflineException e) {
            thrown = true;
        }
        assertTrue(thrown);
        
        // Test that there is an error as the signer is not valid yet
        WorkerStatus status = workerSession.getStatus(new WorkerIdentifier(WORKER1B));
        String errors = status.getFatalErrors().toString();
        assertTrue(errors, errors.contains("xpired"));
    }

    /**
     * Tests all validities: certificate, privatekey and min remaining period.
     * @throws Exception in case of error.
     */
    @Test
    public void test04cRemainingValidity() throws Exception {
        Calendar cal = Calendar.getInstance();

        workerSession.setWorkerProperty(WORKER1C, "CHECKCERTVALIDITY", "True");
        workerSession.setWorkerProperty(WORKER1C, "CHECKCERTPRIVATEKEYVALIDITY",
                "False");
        workerSession.setWorkerProperty(WORKER1C, "MINREMAININGCERTVALIDITY", "0");
        workerSession.reloadConfiguration(WORKER1C);

        //    Certificate with: cert#1: priv=[2015, 2020], cert=[2025, 2030]
        //              cert#2: priv=[2025, 2030], cert=[2015, 2020]
        //
        //
        //    test#1: 	getSignerValidityNotAfter:  cert#1, bCert 	= 2030
        Date d = workerSession.getSigningValidityNotAfter(new WorkerIdentifier(WORKER1C));
        assertNotNull("test#1 not null", d);
        cal.setTime(d);
        assertEquals(2030, cal.get(Calendar.YEAR));

        //    test#2	getSignerValidityNotBefore: cert#1, bCert       = 2025
        d = workerSession.getSigningValidityNotBefore(new WorkerIdentifier(WORKER1C));
        assertNotNull("test#2 not null", d);
        cal.setTime(d);
        assertEquals(2025, cal.get(Calendar.YEAR));

        //    test#3: 	getSignerValidityNotAfter:  cert#1, bPriv       = 2020
        workerSession.setWorkerProperty(WORKER1C, "CHECKCERTVALIDITY", "False");
        workerSession.setWorkerProperty(WORKER1C, "CHECKCERTPRIVATEKEYVALIDITY",
                "True");
        workerSession.reloadConfiguration(WORKER1C);
        d = workerSession.getSigningValidityNotAfter(new WorkerIdentifier(WORKER1C));
        assertNotNull("test#3 not null", d);
        cal.setTime(d);
        assertEquals(2020, cal.get(Calendar.YEAR));

        //    test#4	getSignerValidityNotBefore: cert#1, bPriv       = 2015
        d = workerSession.getSigningValidityNotBefore(new WorkerIdentifier(WORKER1C));
        assertNotNull("test#4 not null", d);
        cal.setTime(d);
        assertEquals(2015, cal.get(Calendar.YEAR));

        //    test#5: 	getSignerValidityNotAfter:  cert#1, bCert, bPriv	  = 2020
        workerSession.setWorkerProperty(WORKER1C, "CHECKCERTVALIDITY", "True");
        workerSession.reloadConfiguration(WORKER1C);
        d = workerSession.getSigningValidityNotAfter(new WorkerIdentifier(WORKER1C));
        assertNotNull("test#5 not null", d);
        cal.setTime(d);
        assertEquals(2020, cal.get(Calendar.YEAR));

        //    test#6		getSignerValidityNotBefore: cert#1, bCert, bPrive = 2015
        d = workerSession.getSigningValidityNotBefore(new WorkerIdentifier(WORKER1C));
        assertNotNull("test#6 not null", d);
        cal.setTime(d);
        assertEquals(2015, cal.get(Calendar.YEAR));

        //    test#7: 	getSignerValidityNotAfter:  cert#1, bCert, r10 		  = 2020
        workerSession.setWorkerProperty(WORKER1C, "CHECKCERTPRIVATEKEYVALIDITY",
                "False");
        workerSession.setWorkerProperty(WORKER1C, "MINREMAININGCERTVALIDITY", "3650");
        workerSession.reloadConfiguration(WORKER1C);
        d = workerSession.getSigningValidityNotAfter(new WorkerIdentifier(WORKER1C));
        assertNotNull("test#7 not null", d);
        cal.setTime(d);
        assertEquals(2020, cal.get(Calendar.YEAR));

        //    test#8		getSignerValidityNotBefore: cert#1, bCert, r10	  = 2015
        d = workerSession.getSigningValidityNotBefore(new WorkerIdentifier(WORKER1C));
        assertNotNull("test#8 not null", d);
        cal.setTime(d);
        assertEquals(2025, cal.get(Calendar.YEAR));

        //    test#9: 	getSignerValidityNotAfter:  cert#1, bCert, r4 		  = 2026
        workerSession.setWorkerProperty(WORKER1C, "MINREMAININGCERTVALIDITY", "1460");
        workerSession.reloadConfiguration(WORKER1C);
        d = workerSession.getSigningValidityNotAfter(new WorkerIdentifier(WORKER1C));
        assertNotNull("test#9 not null", d);
        cal.setTime(d);
        assertEquals(2026, cal.get(Calendar.YEAR));

        //    test#10:	getSignerValidityNotBefore: cert#1, bCert, r4		  = 2025
        d = workerSession.getSigningValidityNotBefore(new WorkerIdentifier(WORKER1C));
        assertNotNull("test#10 not null", d);
        cal.setTime(d);
        assertEquals(2025, cal.get(Calendar.YEAR));

        //    test#21: 	getSignerValidityNotAfter:  cert#2, bCert 		  = 2020
        workerSession.setWorkerProperty(WORKER1D, "CHECKCERTVALIDITY", "True");
        workerSession.setWorkerProperty(WORKER1D, "CHECKCERTPRIVATEKEYVALIDITY",
                "False");
        workerSession.setWorkerProperty(WORKER1D, "MINREMAININGCERTVALIDITY", "0");
        workerSession.reloadConfiguration(WORKER1D);
        d = workerSession.getSigningValidityNotAfter(new WorkerIdentifier(WORKER1D));
        assertNotNull("test#21 not null", d);
        cal.setTime(d);
        assertEquals(2020, cal.get(Calendar.YEAR));

        //    test#22		getSignerValidityNotBefore: cert#2, bCert	  = 2015
        assertNotNull("test#22 not null", d);
        d = workerSession.getSigningValidityNotBefore(new WorkerIdentifier(WORKER1D));
        cal.setTime(d);
        assertEquals(2015, cal.get(Calendar.YEAR));

        //    test#23: 	getSignerValidityNotAfter:  cert#2, bPriv 		  = 2030
        workerSession.setWorkerProperty(WORKER1D, "CHECKCERTVALIDITY", "False");
        workerSession.setWorkerProperty(WORKER1D, "CHECKCERTPRIVATEKEYVALIDITY",
                "True");
        workerSession.reloadConfiguration(WORKER1D);
        d = workerSession.getSigningValidityNotAfter(new WorkerIdentifier(WORKER1D));
        assertNotNull("test#23 not null", d);
        cal.setTime(d);
        assertEquals(2030, cal.get(Calendar.YEAR));

        //    test#24		getSignerValidityNotBefore: cert#2, bPriv	 = 2025
        d = workerSession.getSigningValidityNotBefore(new WorkerIdentifier(WORKER1D));
        assertNotNull("test#24 not null", d);
        cal.setTime(d);
        assertEquals(2025, cal.get(Calendar.YEAR));

        //    test#25: 	getSignerValidityNotAfter:  cert#2, bCert, bPriv	 = 2020
        workerSession.setWorkerProperty(WORKER1D, "CHECKCERTVALIDITY", "True");
        workerSession.reloadConfiguration(WORKER1D);
        d = workerSession.getSigningValidityNotAfter(new WorkerIdentifier(WORKER1D));
        assertNotNull("test#25 not null", d);
        cal.setTime(d);
        assertEquals(2020, cal.get(Calendar.YEAR));

        //    test#26		getSignerValidityNotBefore: cert#2, bCert, bPriv = 2025
        d = workerSession.getSigningValidityNotBefore(new WorkerIdentifier(WORKER1D));
        assertNotNull("test#26 not null", d);
        cal.setTime(d);
        assertEquals(2025, cal.get(Calendar.YEAR));

        //    test#27: 	getSignerValidityNotAfter:  cert#2, bCert, r10 		  = 2010 r10 -> 3650
        workerSession.setWorkerProperty(WORKER1D, "CHECKCERTPRIVATEKEYVALIDITY",
                "False");
        workerSession.setWorkerProperty(WORKER1D, "MINREMAININGCERTVALIDITY", "3650");
        workerSession.reloadConfiguration(WORKER1D);
        d = workerSession.getSigningValidityNotAfter(new WorkerIdentifier(WORKER1D));
        assertNotNull("test#27 not null", d);
        cal.setTime(d);
        assertEquals(2010, cal.get(Calendar.YEAR));

        //    test#28		getSignerValidityNotBefore: cert#2, bCert, r10	  = 2015
        d = workerSession.getSigningValidityNotBefore(new WorkerIdentifier(WORKER1D));
        assertNotNull("test#28 not null", d);
        cal.setTime(d);
        assertEquals(2015, cal.get(Calendar.YEAR));

        //    test#29: 	getSignerValidityNotAfter:  cert#2, bCert, r4 		  = 2016 r4 -> 1460
        workerSession.setWorkerProperty(WORKER1D, "MINREMAININGCERTVALIDITY", "1460");
        workerSession.reloadConfiguration(WORKER1D);
        d = workerSession.getSigningValidityNotAfter(new WorkerIdentifier(WORKER1D));
        assertNotNull("test#29 not null", d);
        cal.setTime(d);
        assertEquals(2016, cal.get(Calendar.YEAR));

        //    test#30:	getSignerValidityNotBefore: cert#2, bCert, r4		  = 2015
        d = workerSession.getSigningValidityNotBefore(new WorkerIdentifier(WORKER1D));
        assertNotNull("test#30 not null", d);
        cal.setTime(d);
        assertEquals(2015, cal.get(Calendar.YEAR));
    }

    private void signHelper(int workerId, int requestId, Map<Integer, byte[]> dataGroups, boolean signerDoesHashing, String digestAlg, String sigAlg) throws Exception {
        // Create expected hashes
        Map<Integer, byte[]> expectedHashes;
        if (signerDoesHashing) {
            MessageDigest d = MessageDigest.getInstance(digestAlg, "BC");
            expectedHashes = new HashMap<>();
            for (Map.Entry<Integer, byte[]> entry : dataGroups.entrySet()) {
                expectedHashes.put(entry.getKey(), d.digest(entry.getValue()));
                d.reset();
            }
        } else {
            expectedHashes = dataGroups;
        }

        SODSignResponse res = (SODSignResponse) processSession.process(new WorkerIdentifier(workerId), new SODSignRequest(requestId, dataGroups), new RemoteRequestContext());
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
        for (Map.Entry<Integer, byte[]> entry : actualDataGroupHashes.entrySet()) {
            assertTrue("DG" + entry.getKey(), Arrays.equals(expectedHashes.get(entry.getKey()), entry.getValue()));
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
    @Test
    public void test05GetStatus() throws Exception {
        StaticWorkerStatus stat = (StaticWorkerStatus) workerSession.getStatus(new WorkerIdentifier(7897));
        assertTrue(stat.getTokenStatus() == WorkerStatus.STATUS_ACTIVE);
    }

    /**
     * Test that setting INCLUDE_CERTIFICATE_LEVELS is not supported.
     * @throws Exception
     */
    @Test
    public void test06IncludeCertificateLevelsNotSupported() throws Exception {
        try {
            workerSession.setWorkerProperty(WORKER1, WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS, "2");
            workerSession.reloadConfiguration(WORKER1);
            
            final List<String> errors = workerSession.getStatus(new WorkerIdentifier(WORKER1)).getFatalErrors();
            
            assertTrue("Should contain error", errors.contains(WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS + " is not supported."));
        } finally {
            workerSession.removeWorkerProperty(WORKER1, WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS);
            workerSession.reloadConfiguration(WORKER1);
        }
    }
    
    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(WORKER1);
        removeWorker(WORKER2);
        removeWorker(WORKER3);
        removeWorker(WORKER4);
        removeWorker(WORKER5);
        removeWorker(WORKER1B);
        removeWorker(WORKER1C);
        removeWorker(WORKER1D);
    }
}
