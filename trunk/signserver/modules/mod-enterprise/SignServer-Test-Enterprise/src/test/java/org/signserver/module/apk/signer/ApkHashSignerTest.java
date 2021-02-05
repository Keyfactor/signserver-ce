/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.apk.signer;

import com.novell.ldap.util.Base64;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import org.apache.log4j.Logger;
import org.junit.Test;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import static org.signserver.module.apk.signer.ApkSignerTest.getProcessSessionS;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests for the ApkHashSigner.
 * 
 * Theese tests requires a running SignServer. For standalone unit tests
 * preferably use ApkHashSignerUnitTest instead.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ApkHashSignerTest {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ApkHashSignerTest.class);

    private static final int WORKER_ID_HASH = 7911;
    private static final String HASH_WORKER_NAME = "TestApkHashSigner";
    private static final int WORKER_ID_ROTATE = 7912;
    private static final String ROTATE_WORKER_NAME = "TestApkRotateSigner";
    private static final int WORKER_ID_OLD = 7913;
    private static final String WORKER_NAME_OLD = "TestApkSignerOld";
    private static final int WORKER_ID_NEW = 7914;
    private static final String WORKER_NAME_NEW = "TestApkSignerNew";

    private final ModulesTestCase helper = new ModulesTestCase();
    private final ProcessSessionRemote processSession = getProcessSessionS();

    private void addApkRotateSigner() throws Exception {
        helper.addApkRotateSigner(WORKER_ID_ROTATE, ROTATE_WORKER_NAME, true);
    }

    private void addApkSignerOld() throws Exception {
        helper.addApkSigner(WORKER_ID_OLD, WORKER_NAME_OLD, true);
    }
    
    private void addApkSignerNew() throws Exception {
        helper.addApkSignerECDSA(WORKER_ID_NEW, WORKER_NAME_NEW, true);
    }
    
    private void addApkHashSigner() throws Exception {
        helper.addApkHashSigner(WORKER_ID_HASH, HASH_WORKER_NAME, true);
    }

    /**
     * Test generating a pre-response with no OTHER_SIGNERS set, and no
     * lineage file. Should only contain the hash signer's own cert chain.
     * 
     * @throws Exception 
     */
    @Test
    public void testPreResponseNoOtherNoLineage() throws Exception {
        LOG.info("testPreResponseNoOtherNoLineage");
        try {
            addApkHashSigner();

            testPreResponse(2, 0, null, null, null);
        } finally {
            helper.removeWorker(WORKER_ID_HASH);
        }
    }

    /**
     * Test generating a pre-response with no OTHER_SIGNERS set, and no
     * lineage file. Using the normal sample code signing certificate to
     * generated a certificate chain with multiple entries.
     * Should only contain the hash signer's own cert chain.
     * 
     * @throws Exception 
     */
    @Test
    public void testPreResponseNoOtherNoLineageNonSelfSigned() throws Exception {
        LOG.info("testPreResponseNoOtherNoLineageNonSelfSigned");
        try {
            addApkHashSigner();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_HASH,
                                                        "DEFAULTKEY",
                                                        "code00003");
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_HASH);

            testPreResponse(2, 0, null, null, null);
        } finally {
            helper.removeWorker(WORKER_ID_HASH);
        }
    }

    /**
     * Test generating a pre-response with no OTHER_SIGNERS set with a lineage
     * content configured. Should contain the hash signer's own certificate
     * and the lineage file contents.
     *
     * @throws Exception 
     */
    @Test
    public void testPreResponseNoOtherWithLineage() throws Exception {
        LOG.info("testPreResponseNoOtherWithLineage");
        try {
            addApkHashSigner();
            addApkSignerOld();
            addApkSignerNew();
            addApkRotateSigner();

            // configure ApkRotateSigner to generate lineage for old and new signer
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_ROTATE,
                                                        "OTHER_SIGNERS",
                                                        WORKER_NAME_OLD + "," +
                                                        WORKER_NAME_NEW);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_ROTATE);

            // configure lineage on ApkHashSigner
            final String lineageContent = createLineageContent();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_HASH,
                                                        "LINEAGE_FILE_CONTENT",
                                                        lineageContent);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_HASH);

            testPreResponse(3, 0, lineageContent, null, null);
        } finally {
            helper.removeWorker(WORKER_ID_HASH);
            helper.removeWorker(WORKER_ID_ROTATE);
            helper.removeWorker(WORKER_ID_OLD);
            helper.removeWorker(WORKER_ID_NEW);
        }
    }

    /**
     * Test generating a pre-response with two OTHER_SIGNERS set, and no
     * lineage file. Should only contain the hash signer's own cert chain and
     * both the other signer's names and chains.
     * 
     * @throws Exception 
     */
    @Test
    public void testPreResponseTwoOtherSignersNoLineage() throws Exception {
        LOG.info("testPreResponseTwoOtherSignersNoLineage");
        try {
            addApkHashSigner();
            addApkSignerOld();
            addApkSignerNew();

            helper.getWorkerSession().setWorkerProperty(WORKER_ID_HASH,
                                                        "OTHER_SIGNERS",
                                                        WORKER_NAME_OLD + "," +
                                                        WORKER_NAME_NEW);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_HASH);

            testPreResponse(6, 2, null,
                            Arrays.asList(WORKER_NAME_OLD, WORKER_NAME_NEW),
                            Arrays.asList(helper.getWorkerSession().getSignerCertificateChain(new WorkerIdentifier(WORKER_ID_OLD)),
                                          helper.getWorkerSession().getSignerCertificateChain(new WorkerIdentifier(WORKER_ID_NEW))));
        } finally {
            helper.removeWorker(WORKER_ID_HASH);
            helper.removeWorker(WORKER_ID_OLD);
            helper.removeWorker(WORKER_ID_NEW);
        }
    }

    /**
     * Test generating a pre-response with one OTHER_SIGNERS set, and no
     * lineage file. Should only contain the hash signer's own cert chain and
     * the other signer's name and chain.
     * 
     * @throws Exception 
     */
    @Test
    public void testPreResponseOneOtherSignersNoLineage() throws Exception {
        LOG.info("testPreResponseOneOtherSignersNoLineage");
        try {
            addApkHashSigner();
            addApkSignerOld();

            helper.getWorkerSession().setWorkerProperty(WORKER_ID_HASH,
                                                        "OTHER_SIGNERS",
                                                        WORKER_NAME_OLD);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_HASH);

            testPreResponse(4, 1, null,
                            Arrays.asList(WORKER_NAME_OLD),
                            Arrays.asList(helper.getWorkerSession().getSignerCertificateChain(new WorkerIdentifier(WORKER_ID_OLD))));
        } finally {
            helper.removeWorker(WORKER_ID_HASH);
            helper.removeWorker(WORKER_ID_OLD);
        }
    }

    private String createLineageContent() throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        final GenericSignRequest request = new GenericSignRequest(200, new byte[0]);
        final RemoteRequestContext context = new RemoteRequestContext();
        final GenericSignResponse response =
                (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_ID_ROTATE),
                                                             request, context);

        return Base64.encode(response.getProcessedData());
    }
    
    private void testPreResponse(final int expectedNumberOfEntries,
                                 final int expectedNumberOfOtherSigners,
                                 final String expectedLineageContent,
                                 final List<String> expectedOtherSignersNames,
                                 final List<List<Certificate>> expectedOtherSignersCertChains)
            throws IllegalRequestException, CryptoTokenOfflineException,
                   SignServerException, IOException, CertificateException {
        // generate pre-response
        final GenericSignRequest request = new GenericSignRequest(200, new byte[0]);
        final RemoteRequestContext context = new RemoteRequestContext();
        final GenericSignResponse response =
                (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_ID_HASH), request, context);
        final byte[] preResponseData = response.getProcessedData();
        final Properties props = new Properties();

        props.load(new ByteArrayInputStream(preResponseData));

        // should only contain two entries (the signer cert chain and number of other signers)
        assertEquals("Number of entries in pre-response: " + new String(preResponseData),
                     expectedNumberOfEntries, props.keySet().size());

        final String preResponseNumberOfOtherSigners =
                props.getProperty("NUMBER_OF_OTHER_SIGNERS");

        assertNotNull("Number of other signers present",
                      preResponseNumberOfOtherSigners);
        assertEquals("Expected number of other signers",
                     expectedNumberOfOtherSigners,
                     Integer.parseInt(preResponseNumberOfOtherSigners));

        final String preResponseCertChain =
                props.getProperty("SIGNER_CERTIFICATE_CHAIN");

        assertNotNull("Signer certificate chain present",
                      preResponseCertChain);

        checkCertificateChain(preResponseCertChain,
                              helper.getWorkerSession().getSignerCertificateChain(new WorkerIdentifier(WORKER_ID_HASH)));

        final String lineageContent = props.getProperty("LINEAGE_FILE_CONTENT");

        assertEquals("Lineage content", expectedLineageContent, lineageContent);

        if (expectedOtherSignersNames != null) {
            for (int i = 0; i < expectedOtherSignersNames.size(); i++) {
                final String foundOtherSignerName =
                        props.getProperty("OTHER_SIGNER_" + i + ".NAME");

                assertEquals("Other signer name",
                             expectedOtherSignersNames.get(i),
                             foundOtherSignerName);
            }
        }

        if (expectedOtherSignersCertChains != null) {
            for (int i = 0; i < expectedOtherSignersCertChains.size(); i++) {
                final String foundOtherCertChain =
                        props.getProperty("OTHER_SIGNER_" + i + ".CERTIFICATE_CHAIN");

                checkCertificateChain(foundOtherCertChain,
                                      expectedOtherSignersCertChains.get(i));
            }
        }
    }

    private void checkCertificateChain(final String certChainProperty,
                                       final List<Certificate> expectedChain) throws CertificateException {
        final String[] chainParts = certChainProperty.split(";");

        assertNotNull("Found cert chain property", certChainProperty);
        assertEquals("Number of certificates in chain", expectedChain.size(),
                     chainParts.length);

        final CertificateFactory certFactory =
                CertificateFactory.getInstance("X.509");
        for (int i = 0; i < expectedChain.size(); i++) {
            final Certificate expectedCert = expectedChain.get(i);
            final ByteArrayInputStream is =
                    new ByteArrayInputStream(Base64.decode(chainParts[i].trim()));
            final Certificate foundCert = certFactory.generateCertificate(is);

            assertEquals("Certificate at position " + i + " in chain",
                         expectedCert, foundCert);
        }
    }
}
