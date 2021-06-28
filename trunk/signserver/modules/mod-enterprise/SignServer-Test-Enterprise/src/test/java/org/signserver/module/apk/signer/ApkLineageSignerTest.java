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

import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.internal.util.ByteBufferDataSource;
import java.io.File;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import org.apache.log4j.Logger;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import static org.signserver.module.apk.signer.ApkSignerTest.getProcessSessionS;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests for the ApkLineageSigner.
 * 
 * This tests requires a running SignServer. For standalone unit tests
 * preferably use ApkLineageSignerUnitTest instead.
 *
 * @author Markus Kilås
 * @author Marcus Lundblad
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@SuppressWarnings("PMD.UnusedFormalParameter") // JUnit requires parameter in constructor
public class ApkLineageSignerTest {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ApkLineageSignerTest.class);

    private static final int WORKER_ID_LINEAGE = 7911;
    private static final String LINEAGE_WORKER_NAME = "TestApkLineageSigner";
    private static final int WORKER_ID_ROTATE = 7911;
    private static final String ROTATE_WORKER_NAME = "TestApkRotateSigner";
    private static final int WORKER_ID_OLD = 7913;
    private static final String WORKER_NAME_OLD = "TestApkSignerOld";
    private static final int WORKER_ID_NEW = 7914;
    private static final String WORKER_NAME_NEW = "TestApkSignerNew";

    private static final String SIGNER1_CERT_SHA256_DIGEST = "d219b8fa222e7ab9a025c306de7ce47ad92505d1dbca7104c0dad55d6997a911";
    private static final String SIGNER2_CERT_SHA256_DIGEST = "f2d1a81082800025a72a6e75928ea2bf9126bd6f0b7167f2682325c35344ad3e";
    private static final String SIGNER1_PUBKEY_SHA256_DIGEST = "81cb5525b00efa1760b13201dac47a1d6e5b4154d78726cfec5a26b27af0c637";
    private static final String SIGNER2_PUBKEY_SHA256_DIGEST = "98af9ef00939f4ec05cd38a07b471fee1747f39156a65a1416763a520ece1aef";

    private final ModulesTestCase helper = new ModulesTestCase();
    private final ProcessSessionRemote processSession = getProcessSessionS();
    private final File apkFile;
    private final File unsignedApkFile;
   
    public ApkLineageSignerTest() throws Exception {
        // existing signed APK without lineage
        apkFile = new File(PathUtil.getAppHome() + File.separator + "res" +
                           File.separator + "test" + File.separator +
                           "HelloApk-signed.apk");
        unsignedApkFile = new File(PathUtil.getAppHome() + File.separator + "res" +
                           File.separator + "test" + File.separator +
                           "HelloApk.apk");
        if (!apkFile.exists() || !unsignedApkFile.exists()) {
            throw new Exception("Missing sample APK files: " +
                                apkFile.getAbsolutePath() + ", " +
                                unsignedApkFile.getAbsolutePath());
        }
    }

    private void addApkRotateSigner() throws Exception {
        helper.addApkRotateSigner(WORKER_ID_ROTATE, ROTATE_WORKER_NAME, true);
    }

    private void addApkSignerOld() throws Exception {
        helper.addApkSigner(WORKER_ID_OLD, WORKER_NAME_OLD, true);
    }
    
    private void addApkSignerNew() throws Exception {
        helper.addApkSigner(WORKER_ID_NEW, WORKER_NAME_NEW, true);
    }
    
    private void addApkLineageSigner() throws Exception {
        helper.addApkLineageSigner(WORKER_ID_LINEAGE, LINEAGE_WORKER_NAME, true);
    }

    private void testPrintCertsWithPrintCertsProperty(final String propertyValue)
            throws Exception {
        try {
            // Add rotate signer (to create initial lineage)
            addApkRotateSigner();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_ROTATE, "DEFAULTKEY",
                                                        "apk00001");
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_ROTATE, "OTHER_SIGNERS",
                                                        WORKER_NAME_OLD + "," +
                                                        WORKER_NAME_NEW);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_ROTATE);
            
            // Add SignerOld
            addApkSignerOld();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_OLD,
                                                        "DEFAULTKEY", "apk00001");
            
            // Add SignerNew
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_OLD);
            addApkSignerNew();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_NEW,
                                                        "DEFAULTKEY", "apk00002");
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_NEW);

            // Create lineage
            GenericSignRequest request = new GenericSignRequest(200, new byte[0]);
            final RemoteRequestContext context = new RemoteRequestContext();

            GenericSignResponse response =
                    (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_ID_ROTATE), request, context);
            final byte[] lineageData = response.getProcessedData();
            final ByteBufferDataSource dataSource =
                    new ByteBufferDataSource(ByteBuffer.wrap(lineageData));
            final SigningCertificateLineage signingCertificateLineage =
                    SigningCertificateLineage.readFromDataSource(dataSource);

            // add lineage signer
            addApkLineageSigner();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_LINEAGE,
                                                        "OTHER_SIGNERS",
                                                        WORKER_NAME_OLD);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_LINEAGE);
            request = new GenericSignRequest(200, lineageData);
            final RequestMetadata metadata = new RequestMetadata();
            metadata.put("PRINT_CERTS", propertyValue);
            context.setMetadata(metadata);
            response =
                    (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_ID_LINEAGE), request, context);

            final byte[] data = response.getProcessedData();
            final String output = new String(data, StandardCharsets.UTF_8);

            assertTrue("Should contain certificate DN for old signer: " + output,
                       output.contains("Signer #1 in lineage certificate DN: CN=APK Signer 00001, O=SignServer, C=SE"));
            assertTrue("Should contain certificate DN for new signer: " + output,
                       output.contains("Signer #2 in lineage certificate DN: CN=APK Signer 00002, O=SignServer, C=SE"));
            assertTrue("Should contain certificate digest for old signer: " + output,
                       output.contains("Signer #1 in lineage certificate SHA-256 digest: " +
                                       SIGNER1_CERT_SHA256_DIGEST));
            assertTrue("Should contain certificate digest for new signer: " + output,
                       output.contains("Signer #2 in lineage certificate SHA-256 digest: " +
                                       SIGNER2_CERT_SHA256_DIGEST));
            assertTrue("Should contain pubkey digest for old signer: " + output,
                       output.contains("Signer #1 in lineage public key SHA-256 digest: " +
                                       SIGNER1_PUBKEY_SHA256_DIGEST));
            assertTrue("Should contain pubkey digest for new signer: " + output,
                       output.contains("Signer #2 in lineage public key SHA-256 digest: " +
                                       SIGNER2_PUBKEY_SHA256_DIGEST));
        } finally {
            helper.removeWorker(WORKER_ID_LINEAGE);
            helper.removeWorker(WORKER_ID_ROTATE);
            helper.removeWorker(WORKER_ID_OLD);
            helper.removeWorker(WORKER_ID_NEW);
        }
    }

    /**
     * Test request print certs output.
     *
     * @throws Exception 
     */
    @Test
    public void testPrintCerts() throws Exception {
        LOG.info("testPrintCerts");
        testPrintCertsWithPrintCertsProperty("true");
    }

    /**
     * Test request print certs output. Using upper-case request property value.
     *
     * @throws Exception 
     */
    @Test
    public void testPrintCertsUpperCase() throws Exception {
        LOG.info("testPrintCertsUpperCase");
        testPrintCertsWithPrintCertsProperty("TRUE");
    }

    private void testModifyLineageWithPrintCertsProperty(final String printCertsProperty)
            throws Exception {
        try {
            // Add rotate signer (to create initial lineage)
            addApkRotateSigner();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_ROTATE, "DEFAULTKEY",
                                                        "apk00001");
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_ROTATE, "OTHER_SIGNERS",
                                                        WORKER_NAME_OLD + "," +
                                                        WORKER_NAME_NEW);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_ROTATE);
            
            // Add SignerOld
            addApkSignerOld();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_OLD,
                                                        "DEFAULTKEY", "apk00001");
            
            // Add SignerNew
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_OLD);
            addApkSignerNew();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_NEW,
                                                        "DEFAULTKEY", "apk00002");
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_NEW);

            // Create lineage
            final GenericSignRequest request = new GenericSignRequest(200, new byte[0]);
            final RemoteRequestContext context = new RemoteRequestContext();
            final GenericSignResponse response =
                    (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_ID_ROTATE), request, context);
            final byte[] lineageData = response.getProcessedData();
            final ByteBufferDataSource dataSource =
                    new ByteBufferDataSource(ByteBuffer.wrap(lineageData));
            final SigningCertificateLineage signingCertificateLineage =
                    SigningCertificateLineage.readFromDataSource(dataSource);
            
            if (signingCertificateLineage.size() != 2) {
                throw new Exception("Expected 2 signers in lineage");
            }

            final X509Certificate oldCert =
                    (X509Certificate) helper.getWorkerSession().getSignerCertificate(new WorkerIdentifier(WORKER_ID_OLD));
            final X509Certificate newCert =
                    (X509Certificate) helper.getWorkerSession().getSignerCertificate(new WorkerIdentifier(WORKER_ID_NEW));
            
            if (!signingCertificateLineage.isCertificateInLineage(oldCert)) {
                throw new Exception("Expected: Lineage includes old cert");
            }
            if (!signingCertificateLineage.isCertificateInLineage(newCert)) {
                throw new Exception("Expected: Lineage includes new cert");
            }
            
            // Get original capabilities
            final SigningCertificateLineage.SignerCapabilities originalOldSignerCapabilities = signingCertificateLineage.getSignerCapabilities(oldCert);
            final SigningCertificateLineage.SignerCapabilities originalNewSignerCapabilities = signingCertificateLineage.getSignerCapabilities(newCert);
            
            // Add lineage signer (will be modified in test method so the reload is there)
            addApkLineageSigner();
            
            // Test 1 capability change for oldCert
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_LINEAGE, WorkerConfig.OTHER_SIGNERS, WORKER_NAME_OLD);
            assertChangedProperty(oldCert, ApkLineageSigner.PROPERTY_SET_AUTH, false, signingCertificateLineage, lineageData, newCert, printCertsProperty);
            assertChangedProperty(oldCert, ApkLineageSigner.PROPERTY_SET_INSTALLED_DATA, false, signingCertificateLineage, lineageData, newCert, printCertsProperty);
            assertChangedProperty(oldCert, ApkLineageSigner.PROPERTY_SET_PERMISSION, false, signingCertificateLineage, lineageData, newCert, printCertsProperty);
            assertChangedProperty(oldCert, ApkLineageSigner.PROPERTY_SET_ROLLBACK, true, signingCertificateLineage, lineageData, newCert, printCertsProperty);
            assertChangedProperty(oldCert, ApkLineageSigner.PROPERTY_SET_SHARED_UID, false, signingCertificateLineage, lineageData, newCert, printCertsProperty);
            
            // Test 1 capability change for newCert
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_LINEAGE, WorkerConfig.OTHER_SIGNERS, WORKER_NAME_NEW);
            assertChangedProperty(newCert, ApkLineageSigner.PROPERTY_SET_AUTH, false, signingCertificateLineage, lineageData, oldCert, printCertsProperty);
            assertChangedProperty(newCert, ApkLineageSigner.PROPERTY_SET_INSTALLED_DATA, false, signingCertificateLineage, lineageData, oldCert, printCertsProperty);
            assertChangedProperty(newCert, ApkLineageSigner.PROPERTY_SET_PERMISSION, false, signingCertificateLineage, lineageData, oldCert, printCertsProperty);
            assertChangedProperty(newCert, ApkLineageSigner.PROPERTY_SET_ROLLBACK, true, signingCertificateLineage, lineageData, oldCert, printCertsProperty);
            assertChangedProperty(newCert, ApkLineageSigner.PROPERTY_SET_SHARED_UID, false, signingCertificateLineage, lineageData, oldCert, printCertsProperty);
            
        } finally {
            helper.removeWorker(WORKER_ID_LINEAGE);
            helper.removeWorker(WORKER_ID_ROTATE);
            helper.removeWorker(WORKER_ID_OLD);
            helper.removeWorker(WORKER_ID_NEW);
        }
    }

    /**
     * Test modifying one capability at a time for old and new signer.
     * 
     * @throws Exception 
     */
    @Test
    public void testModifyLineage() throws Exception {
        LOG.info("testModifyLineage");
        testModifyLineageWithPrintCertsProperty(null);
    }

    /**
     * Test modifying one capability at a time for old and new signer.
     * Explicitly set PRINT_CERTS=false.
     * 
     * @throws Exception 
     */
    @Test
    public void testModifyLineageExplicitPrintCertsFalse() throws Exception {
        LOG.info("testNewLineageExplicitPrintCertsFalse");
        testModifyLineageWithPrintCertsProperty("false");
    }

    /**
     * Test modifying one capability at a time for old and new signer.
     * Explicitly set PRINT_CERTS=FALSE (in upper case).
     * 
     * @throws Exception 
     */
    @Test
    public void testModifyLineageExplicitPrintCertsFalseUpperCase() throws Exception {
        LOG.info("testNewLineageExplicitPrintCertsFalseUpperCase");
        testModifyLineageWithPrintCertsProperty("FALSE");
    }

    /**
     * Test modifying one capability at a time for old and new signer.
     * Explicitly set PRINT_CERTS= (empty value). Should be equivalent of not
     * requesting to print certs.
     * 
     * @throws Exception 
     */
    @Test
    public void testModifyLineageExplicitPrintCertsEmpty() throws Exception {
        LOG.info("testNewLineageExplicitPrintCertsEmpty");
        testModifyLineageWithPrintCertsProperty("");
    }
    
    private SigningCertificateLineage modifyLineage(final byte[] origLineage,
                                                    final String modifyProperty,
                                                    final boolean newValue,
                                                    final String printCertsProperty)
            throws Exception {
        // Configure lineage worker
        // remove previous SET_ values
        helper.getWorkerSession().removeWorkerProperty(WORKER_ID_LINEAGE, ApkLineageSigner.PROPERTY_SET_AUTH);
        helper.getWorkerSession().removeWorkerProperty(WORKER_ID_LINEAGE, ApkLineageSigner.PROPERTY_SET_INSTALLED_DATA);
        helper.getWorkerSession().removeWorkerProperty(WORKER_ID_LINEAGE, ApkLineageSigner.PROPERTY_SET_PERMISSION);
        helper.getWorkerSession().removeWorkerProperty(WORKER_ID_LINEAGE, ApkLineageSigner.PROPERTY_SET_ROLLBACK);
        helper.getWorkerSession().removeWorkerProperty(WORKER_ID_LINEAGE, ApkLineageSigner.PROPERTY_SET_SHARED_UID);

        // set new value for capability to modify
        helper.getWorkerSession().setWorkerProperty(WORKER_ID_LINEAGE, modifyProperty, String.valueOf(newValue));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID_LINEAGE);
        
        // Create new lineage
        final GenericSignRequest request = new GenericSignRequest(200, origLineage);
        final RemoteRequestContext context = new RemoteRequestContext();
        if (printCertsProperty != null) {
            final RequestMetadata metadata = new RequestMetadata();
            metadata.put("PRINT_CERTS", printCertsProperty);
            context.setMetadata(metadata);
        }
        final GenericSignResponse response =
                (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_ID_LINEAGE), request, context);
        final byte[] lineageData = response.getProcessedData();
        final ByteBufferDataSource dataSource =
                new ByteBufferDataSource(ByteBuffer.wrap(lineageData));
        final SigningCertificateLineage newLineage =
                SigningCertificateLineage.readFromDataSource(dataSource);
        
        return newLineage;
    }

    private void assertChangedProperty(final X509Certificate changedCert,
                                       final String changedPropertyName,
                                       final boolean changedPropertyValue,
                                       final SigningCertificateLineage originalLineage,
                                       final byte[] originalLineageData,
                                       final X509Certificate unchangedCert,
                                       final String printCertsProperty)
            throws Exception {
        // Request the new linage
        SigningCertificateLineage newLineage =
                modifyLineage(originalLineageData, changedPropertyName,
                              changedPropertyValue, printCertsProperty);
        
        // Get the capabilities
        SigningCertificateLineage.SignerCapabilities newChangedSignerCapabilities = newLineage.getSignerCapabilities(changedCert);
        SigningCertificateLineage.SignerCapabilities newUnchangedSignerCapabilities = newLineage.getSignerCapabilities(unchangedCert);
        SigningCertificateLineage.SignerCapabilities originalChangedSignerCapabilities = originalLineage.getSignerCapabilities(changedCert);
        SigningCertificateLineage.SignerCapabilities originalUnchangedSignerCapabilities = originalLineage.getSignerCapabilities(unchangedCert);
        
        // Check that the property has changed and nothing else
        assertUnchangedCapabilityExceptFor(newChangedSignerCapabilities, originalChangedSignerCapabilities, changedPropertyName, changedPropertyValue);
        
        // Check that no capabilities has changed for the other signer
        originalUnchangedSignerCapabilities.equals(newUnchangedSignerCapabilities);
    }
    
    private void assertUnchangedCapabilityExceptFor(SigningCertificateLineage.SignerCapabilities newCapabilities, SigningCertificateLineage.SignerCapabilities origCapabilities, String name, boolean expectedValue) throws Exception {
        HashMap<String, Boolean> newCap = new HashMap<>();
        HashMap<String, Boolean> origCap = new HashMap<>();
        
        newCap.put(ApkLineageSigner.PROPERTY_SET_AUTH, newCapabilities.hasAuth());
        newCap.put(ApkLineageSigner.PROPERTY_SET_INSTALLED_DATA, newCapabilities.hasInstalledData());
        newCap.put(ApkLineageSigner.PROPERTY_SET_PERMISSION, newCapabilities.hasPermission());
        newCap.put(ApkLineageSigner.PROPERTY_SET_ROLLBACK, newCapabilities.hasRollback());
        newCap.put(ApkLineageSigner.PROPERTY_SET_SHARED_UID, newCapabilities.hasSharedUid());
        
        origCap.put(ApkLineageSigner.PROPERTY_SET_AUTH, origCapabilities.hasAuth());
        origCap.put(ApkLineageSigner.PROPERTY_SET_INSTALLED_DATA, origCapabilities.hasInstalledData());
        origCap.put(ApkLineageSigner.PROPERTY_SET_PERMISSION, origCapabilities.hasPermission());
        origCap.put(ApkLineageSigner.PROPERTY_SET_ROLLBACK, origCapabilities.hasRollback());
        origCap.put(ApkLineageSigner.PROPERTY_SET_SHARED_UID, origCapabilities.hasSharedUid());
        
        // Modify the one that should be changed.
        origCap.put(name, expectedValue);
        
        assertEquals("No changes expected expected for " + name, origCap, newCap);
    }

}
