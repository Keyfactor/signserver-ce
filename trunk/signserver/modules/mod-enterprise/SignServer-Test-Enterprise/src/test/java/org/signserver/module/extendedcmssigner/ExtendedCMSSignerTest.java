/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.extendedcmssigner;

import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import javax.naming.NamingException;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Test;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.ServiceLocator;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.server.FixedTimeSource;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests using ExtendedCMSSigner with timestamping.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ExtendedCMSSignerTest extends ModulesTestCase {
    
    private static final int WORKER_ID = 8901;
    private static final String WORKER_NAME = "TestExtendedCMSSigner";
    private static final int TS_ID = 8902;
    private static final String TS_NAME = "TestTimeStampSigner";
    
    private static WorkerSessionRemote workerSession = getWorkerSessionS();
    private static ProcessSessionRemote processSession = getProcessSessionS();
    
    private static final String TEST_CONTENT = "foo";
    
    protected static WorkerSessionRemote getWorkerSessionS() {
        if (workerSession == null) {
            try {
                workerSession = ServiceLocator.getInstance().lookupRemote(
                    WorkerSessionRemote.class);
            } catch (NamingException ex) {
                fail("Could not lookup WorkerSession: " + ex.getMessage());
            }
        }
        return workerSession;
    }
    
    protected static ProcessSessionRemote getProcessSessionS() {
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
    
    /**
     * Test signing and timestamping with an internal TSA.
     * 
     * @throws Exception 
     */
    @Test
    public void testSigningWithInternalTSAServerSide() throws Exception {
        testSigningWithInternalTSA(false, null, null);
    }
    
    
    /**
     * Test signing with client side hash, SHA1.
     * 
     * @throws Exception 
     */
    @Test
    public void testSigningWithInternalTSAClientSideSHA1() throws Exception {
        testSigningWithInternalTSA(true, "SHA1", "SHA1");
    }
    
    /**
     * Test signing with client side hash, SHA-256.
     * 
     * @throws Exception 
     */
    @Test
    public void testSigningWithInternalTSAClientSideSHA256() throws Exception {
        testSigningWithInternalTSA(true, "SHA256", "SHA-256");
    }
    
    /**
     * Test signing with client side hash, SHA-512.
     * 
     * @throws Exception 
     */
    @Test
    public void testSigningWithInternalTSAClientSideSHA512() throws Exception {
        testSigningWithInternalTSA(true, "SHA512", "SHA-512");
    }
    
    public void testSigningWithInternalTSA(final boolean clientSide,
                                           final String messageDigestParam,
                                           final String hashDigestAlgo)
            throws Exception {
        try {
            final Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner(ExtendedCMSSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "ALLOW_CLIENTSIDEHASHING_OVERRIDE", "true");
            workerSession.setWorkerProperty(WORKER_ID, "ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA1,SHA-256,SHA-512");
            workerSession.setWorkerProperty(WORKER_ID, "SIGNATUREALGORITHM", "SHA256withRSA");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            signAndAssertOk(WORKER_ID, time, clientSide, messageDigestParam, hashDigestAlgo);
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }
    
    /**
     * Test signing and timestamping with an external TSA.
     * 
     * @throws Exception 
     */
    @Test
    public void testSigningWithExternalTSAServerSide() throws Exception {
        testSigningWithExternalTSA(false, null, null);
    }
    
    /**
     * Test signing with client side hash, SHA1.
     * 
     * @throws Exception 
     */
    @Test
    public void testSigningWithExternaTSAClientSideSHA1() throws Exception {
        testSigningWithExternalTSA(true, "SHA1", "SHA1");
    }
    
    /**
     * Test signing with client side hash, SHA-256.
     * 
     * @throws Exception 
     */
    @Test
    public void testSigningWithExternalTSAClientSideSHA256() throws Exception {
        testSigningWithExternalTSA(true, "SHA256", "SHA-256");
    }
    
    /**
     * Test signing with client side hash, SHA-512.
     * 
     * @throws Exception 
     */
    @Test
    public void testSigningWithExternalTSAClientSideSHA512() throws Exception {
        testSigningWithExternalTSA(true, "SHA512", "SHA-512");
    }
    
    public void testSigningWithExternalTSA(final boolean clientSide,
                                           final String messageDigestParam,
                                           final String hashDigestAlgo) throws Exception {
        try {
            final Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            addTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner(ExtendedCMSSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_URL", "http://localhost:8080/signserver/tsa?workerName=" + TS_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "ALLOW_CLIENTSIDEHASHING_OVERRIDE", "true");
            workerSession.setWorkerProperty(WORKER_ID, "ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA1,SHA-256,SHA-512");
            workerSession.setWorkerProperty(WORKER_ID, "SIGNATUREALGORITHM", "SHA256withRSA");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            signAndAssertOk(WORKER_ID, time, clientSide, messageDigestParam, hashDigestAlgo);
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }

    private void signAndAssertOk(final int workerId, final Date timestamp,
                                 final boolean clientSide,
                                 final String messageDigestParam,
                                 final String clientSideHashAlgo)
            throws Exception {
        final int reqid = 42;
        final byte[] toBeSigned;
        final RequestMetadata metadata = new RequestMetadata();
        final RemoteRequestContext requestContext =
                new RemoteRequestContext(metadata);

        if (clientSide) {
            final MessageDigest md = MessageDigest.getInstance(messageDigestParam);
            
            toBeSigned = md.digest(TEST_CONTENT.getBytes());
            metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
            metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", clientSideHashAlgo); 
        } else {
            toBeSigned = TEST_CONTENT.getBytes();
        }
        
        final GenericSignRequest signRequest =
                new GenericSignRequest(reqid, toBeSigned);
        
        final GenericSignResponse res =
                (GenericSignResponse) processSession.process(new WorkerIdentifier(workerId), signRequest, requestContext);
        final byte[] data = res.getProcessedData();
   
        // Answer to right question
        assertSame("Request ID", reqid, res.getRequestID());

        // Check certificate returned
        final Certificate signercert = res.getSignerCertificate();
        assertNotNull("Signer certificate", signercert);

        final CMSSignedData signedData;

        if (clientSide) {
            signedData = new CMSSignedData(new CMSProcessableByteArray(TEST_CONTENT.getBytes()), data);
        } else {
            signedData = new CMSSignedData(data);
        }

        if (!clientSide) {
            // Check that the signed data contains the document (i.e. not detached)
            final byte[] content = (byte[]) signedData.getSignedContent()
                    .getContent();
            assertEquals("Signed document", TEST_CONTENT, new String(content));
        }

        // Get signers
        final Collection signers = signedData.getSignerInfos().getSigners();
        final SignerInformation signer
                = (SignerInformation) signers.iterator().next();

        final SignerInformationVerifier sigVerifier =
                new JcaSignerInfoVerifierBuilder(new JcaDigestCalculatorProviderBuilder().build()).setProvider("BC").build(signercert.getPublicKey());
        
        // Verify using the signer's certificate
        assertTrue("Verification using signer certificate",
                signer.verify(sigVerifier));

        final Attribute tsAttr = signer.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
        assertNotNull("Unsigned attribute present", tsAttr);
        
        final TimeStampToken tst = new TimeStampToken(new CMSSignedData(tsAttr.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
        
        assertEquals("Timestamp time equals", timestamp, tst.getTimeStampInfo().getGenTime());
    }
}
