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
import java.security.cert.X509Certificate;
import java.util.Optional;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static junit.framework.TestCase.fail;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import static org.signserver.module.apk.signer.ApkSignerTest.getProcessSessionS;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests for the ApkRotateSigner.
 * 
 * This tests requires a running SignServer. For standalone unit tests
 * preferably use ApkRotateSignerUnitTest instead.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@SuppressWarnings("PMD.UnusedFormalParameter") // JUnit requires parameter in constructor
public class ApkRotateSignerTest {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ApkRotateSignerTest.class);

    private static final int WORKER_ID = 8912;
    private static final String WORKER_NAME = "TestApkRotateSigner";
    private static final int WORKER_ID_OLD = 8913;
    private static final String WORKER_NAME_OLD = "TestApkSignerOld";
    private static final int WORKER_ID_NEW = 8914;
    private static final String WORKER_NAME_NEW = "TestApkSignerNew";

    private final ModulesTestCase helper = new ModulesTestCase();
    private final ProcessSessionRemote processSession = getProcessSessionS();
    private final File apkFile;
    private final File unsignedApkFile;
   
    public ApkRotateSignerTest() throws Exception {
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
        helper.addApkRotateSigner(WORKER_ID, WORKER_NAME, true);
    }

    private void addApkSignerOld() throws Exception {
        helper.addApkSigner(WORKER_ID_OLD, WORKER_NAME_OLD, true);
    }
    
    private void addApkSignerNew() throws Exception {
        helper.addApkSigner(WORKER_ID_NEW, WORKER_NAME_NEW, true);
    }

    private void setCapsProperties(final Optional<Integer> minSdkVersion,
                                final Optional<Boolean> oldSetInstalledData,
                                final Optional<Boolean> oldSetSharedUid,
                                final Optional<Boolean> oldSetPermission,
                                final Optional<Boolean> oldSetRollback,
                                final Optional<Boolean> oldSetAuth,
                                final Optional<Boolean> newSetInstalledData,
                                final Optional<Boolean> newSetSharedUid,
                                final Optional<Boolean> newSetPermission,
                                final Optional<Boolean> newSetRollback,
                                final Optional<Boolean> newSetAuth) {
        if (minSdkVersion.isPresent()) {
            helper.getWorkerSession().setWorkerProperty(WORKER_ID,
                                                        "MIN_SDK_VERSION",
                                                        Integer.toString(minSdkVersion.get()));
        }
        if (oldSetInstalledData.isPresent()) {
            helper.getWorkerSession().setWorkerProperty(WORKER_ID,
                                                        "OLD_SET_INSTALLED_DATA",
                                                        Boolean.toString(oldSetInstalledData.get()));
        }
        if (oldSetSharedUid.isPresent()) {
            helper.getWorkerSession().setWorkerProperty(WORKER_ID,
                                                        "OLD_SET_SHARED_UID",
                                                        Boolean.toString(oldSetSharedUid.get()));
        }
        if (oldSetPermission.isPresent()) {
            helper.getWorkerSession().setWorkerProperty(WORKER_ID,
                                                        "OLD_SET_PERMISSION",
                                                        Boolean.toString(oldSetPermission.get()));
        }
        if (oldSetRollback.isPresent()) {
            helper.getWorkerSession().setWorkerProperty(WORKER_ID,
                                                        "OLD_SET_ROLLBACK",
                                                        Boolean.toString(oldSetRollback.get()));
        }
        if (oldSetAuth.isPresent()) {
            helper.getWorkerSession().setWorkerProperty(WORKER_ID,
                                                        "OLD_SET_AUTH",
                                                        Boolean.toString(oldSetAuth.get()));
        }
        if (newSetInstalledData.isPresent()) {
            helper.getWorkerSession().setWorkerProperty(WORKER_ID,
                                                        "NEW_SET_INSTALLED_DATA",
                                                        Boolean.toString(newSetInstalledData.get()));
        }
        if (newSetSharedUid.isPresent()) {
            helper.getWorkerSession().setWorkerProperty(WORKER_ID,
                                                        "NEW_SET_SHARED_UID",
                                                        Boolean.toString(newSetSharedUid.get()));
        }
        if (newSetPermission.isPresent()) {
            helper.getWorkerSession().setWorkerProperty(WORKER_ID,
                                                        "NEW_SET_PERMISSION",
                                                        Boolean.toString(newSetPermission.get()));
        }
        if (newSetRollback.isPresent()) {
            helper.getWorkerSession().setWorkerProperty(WORKER_ID,
                                                        "NEW_SET_ROLLBACK",
                                                        Boolean.toString(newSetRollback.get()));
        }
        if (newSetAuth.isPresent()) {
            helper.getWorkerSession().setWorkerProperty(WORKER_ID,
                                                        "NEW_SET_AUTH",
                                                        Boolean.toString(newSetAuth.get()));
        }
    }
    
    private void testNewLineage(final Optional<Integer> minSdkVersion,
                                final Optional<Boolean> oldSetInstalledData,
                                final Optional<Boolean> oldSetSharedUid,
                                final Optional<Boolean> oldSetPermission,
                                final Optional<Boolean> oldSetRollback,
                                final Optional<Boolean> oldSetAuth,
                                final Optional<Boolean> newSetInstalledData,
                                final Optional<Boolean> newSetSharedUid,
                                final Optional<Boolean> newSetPermission,
                                final Optional<Boolean> newSetRollback,
                                final Optional<Boolean> newSetAuth)
            throws Exception {
        try {
            addApkRotateSigner();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "DEFAULTKEY",
                                                        "apk00001");
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "OTHER_SIGNERS",
                                                        WORKER_NAME_OLD + "," +
                                                        WORKER_NAME_NEW);
            setCapsProperties(minSdkVersion, oldSetInstalledData,
                              oldSetSharedUid, oldSetPermission,
                              oldSetRollback, oldSetAuth,
                              newSetInstalledData, newSetSharedUid,
                              newSetPermission, newSetRollback, newSetAuth);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);

            addApkSignerOld();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_OLD,
                                                        "DEFAULTKEY", "apk00001");
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_OLD);

            addApkSignerNew();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_NEW,
                                                        "DEFAULTKEY", "apk00002");
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_NEW);

            final GenericSignRequest request = new GenericSignRequest(200, new byte[0]);
            final RemoteRequestContext context = new RemoteRequestContext();

            final GenericSignResponse response =
                    (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_ID), request, context);
            final byte[] lineageData = response.getProcessedData();
            
            final ByteBufferDataSource dataSource =
                    new ByteBufferDataSource(ByteBuffer.wrap(lineageData));
            final SigningCertificateLineage signingCertificateLineage =
                    SigningCertificateLineage.readFromDataSource(dataSource);
            
            assertEquals("Number of signers in lineage", 2,
                         signingCertificateLineage.size());

            final X509Certificate oldCert =
                    (X509Certificate) helper.getWorkerSession().getSignerCertificate(new WorkerIdentifier(WORKER_ID_OLD));
            final X509Certificate newCert =
                    (X509Certificate) helper.getWorkerSession().getSignerCertificate(new WorkerIdentifier(WORKER_ID_NEW));
            
            assertTrue("Lineage includes old cert",
                       signingCertificateLineage.isCertificateInLineage(oldCert));
            assertTrue("Lineage includes new cert",
                       signingCertificateLineage.isCertificateInLineage(newCert));

            final SigningCertificateLineage.SignerCapabilities oldCaps =
                        signingCertificateLineage.getSignerCapabilities(oldCert);
            final SigningCertificateLineage.SignerCapabilities newCaps =
                        signingCertificateLineage.getSignerCapabilities(newCert);

            if (oldSetInstalledData.isPresent()) {
                assertEquals("Old set installed data cap",
                             oldSetInstalledData.get().booleanValue(),
                             oldCaps.hasInstalledData());
            }
            if (oldSetSharedUid.isPresent()) {
                assertEquals("Old set shared UID cap",
                             oldSetSharedUid.get().booleanValue(),
                             oldCaps.hasSharedUid());
            }
            if (oldSetPermission.isPresent()) {
                assertEquals("Old set permission cap",
                             oldSetPermission.get().booleanValue(),
                             oldCaps.hasPermission());
            }
            if (oldSetRollback.isPresent()) {
                assertEquals("Old set rollback cap",
                             oldSetRollback.get().booleanValue(),
                             oldCaps.hasRollback());
            }
            if (oldSetAuth.isPresent()) {
                assertEquals("Old set auth cap",
                             oldSetAuth.get().booleanValue(),
                             oldCaps.hasAuth());
            }
            if (newSetInstalledData.isPresent()) {
                assertEquals("New set installed data cap",
                             newSetInstalledData.get().booleanValue(),
                             newCaps.hasInstalledData());
            }
            if (newSetSharedUid.isPresent()) {
                assertEquals("New set shared UID cap",
                             newSetSharedUid.get().booleanValue(),
                             newCaps.hasSharedUid());
            }
            if (newSetPermission.isPresent()) {
                assertEquals("New set permission cap",
                             newSetPermission.get().booleanValue(),
                             newCaps.hasPermission());
            }
            if (newSetRollback.isPresent()) {
                assertEquals("New set rollback cap",
                             newSetRollback.get().booleanValue(),
                             newCaps.hasRollback());
            }
            if (newSetAuth.isPresent()) {
                assertEquals("New set auth cap",
                             newSetAuth.get().booleanValue(),
                             newCaps.hasAuth());
            }
            // TODO: I didn't find a way to check min SDK version set in
            // a lineage using the API...
        } finally {
            helper.removeWorker(WORKER_ID);
            helper.removeWorker(WORKER_ID_OLD);
            helper.removeWorker(WORKER_ID_NEW);
        }
    }
    
    /**
     * Test creating a new lineage by using an empty input.
     *
     * @throws Exception 
     */
    @Test
    public void testNewLineage() throws Exception {
        LOG.info("testNewLineage");
        testNewLineage(Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty());
    }

    /**
     * Test creating a new lineage by using an empty input. Setting false
     * for installed data capability of old signer.
     *
     * @throws Exception 
     */
    @Test
    public void testNewLineageOldInstalledDataFalse() throws Exception {
        LOG.info("testNewLineageOldInstalledDataFalse");
        testNewLineage(Optional.empty(), Optional.of(false), Optional.empty(),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty());
    }

    /**
     * Test creating a new lineage by using an empty input. Setting false
     * for shared UID capability of old signer.
     *
     * @throws Exception 
     */
    @Test
    public void testNewLineageOldSharedUidFalse() throws Exception {
        LOG.info("testNewLineageOldSharedUidFalse");
        testNewLineage(Optional.empty(), Optional.empty(), Optional.of(false),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty());
    }

    /**
     * Test creating a new lineage by using an empty input. Setting false
     * for permission capability of old signer.
     *
     * @throws Exception 
     */
    @Test
    public void testNewLineageOldPermissionFalse() throws Exception {
        LOG.info("testNewLineageOldPermissionFalse");
        testNewLineage(Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.of(false), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty());
    }

    /**
     * Test creating a new lineage by using an empty input. Setting true
     * for rollback capability of old signer.
     *
     * @throws Exception 
     */
    @Test
    public void testNewLineageOldRollbackTrue() throws Exception {
        LOG.info("testNewLineageOldRollbackTrue");
        testNewLineage(Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.of(true), Optional.empty(),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty());
    }

    /**
     * Test creating a new lineage by using an empty input. Setting false
     * for auth capability of old signer.
     *
     * @throws Exception 
     */
    @Test
    public void testNewLineageOldAuthFalse() throws Exception {
        LOG.info("testNewLineageOldAuthFalse");
        testNewLineage(Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty(), Optional.of(false),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty());
    }

    /**
     * Test creating a new lineage by using an empty input. Setting false
     * for installed data capability of new signer.
     *
     * @throws Exception 
     */
    @Test
    public void testNewLineageNewInstalledDataFalse() throws Exception {
        LOG.info("testNewLineageNewInstalledDataFalse");
        testNewLineage(Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.of(false), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty());
    }

    /**
     * Test creating a new lineage by using an empty input. Setting false
     * for shared UID capability of new signer.
     *
     * @throws Exception 
     */
    @Test
    public void testNewLineageNewSharedUidFalse() throws Exception {
        LOG.info("testNewLineageNewSharedUidFalse");
        testNewLineage(Optional.empty(), Optional.empty(), Optional.of(false),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.of(false), Optional.empty(),
                       Optional.empty(), Optional.empty());
    }

    /**
     * Test creating a new lineage by using an empty input. Setting false
     * for permission capability of new signer.
     *
     * @throws Exception 
     */
    @Test
    public void testNewLineageNewPermissionFalse() throws Exception {
        LOG.info("testNewLineageNewPermissionFalse");
        testNewLineage(Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty(), Optional.of(false),
                       Optional.empty(), Optional.empty());
    }

    /**
     * Test creating a new lineage by using an empty input. Setting true
     * for rollback capability of new signer.
     *
     * @throws Exception 
     */
    @Test
    public void testNewLineageNewRollbackTrue() throws Exception {
        LOG.info("testNewLineageNewRollbackTrue");
        testNewLineage(Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.of(true), Optional.empty());
    }

    /**
     * Test creating a new lineage by using an empty input. Setting false
     * for auth capability of new signer.
     *
     * @throws Exception 
     */
    @Test
    public void testNewLineageNewAuthFalse() throws Exception {
        LOG.info("testNewLineageNewAuthFalse");
        testNewLineage(Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.of(false));
    }

    /**
     * Test creating a new lineage by using an empty input. Setting a min SDK
     * version.
     * Note: as of now the test does not verify the SDK version of the result.
     *
     * @throws Exception 
     */
    @Test
    public void testNewLineageMinSdkVersion() throws Exception {
        LOG.info("testNewLineageMinSdkVersion");
        testNewLineage(Optional.of(29), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty(), Optional.empty(),
                       Optional.empty(), Optional.empty());
    }

    private void assertUpdatedCaps(final Optional<Boolean> newSetInstalledData,
                                   final Optional<Boolean> newSetSharedUid,
                                   final Optional<Boolean> newSetPermission,
                                   final Optional<Boolean> newSetRollback,
                                   final Optional<Boolean> newSetAuth,
                                   SigningCertificateLineage.SignerCapabilities caps) {
        if (newSetInstalledData.isPresent()) {
            assertEquals("New set installed data cap",
                         newSetInstalledData.get().booleanValue(),
                         caps.hasInstalledData());
        }
        if (newSetSharedUid.isPresent()) {
            assertEquals("New set shared UID cap",
                         newSetSharedUid.get().booleanValue(),
                         caps.hasSharedUid());
        }
        if (newSetPermission.isPresent()) {
            assertEquals("New set permission cap",
                         newSetPermission.get().booleanValue(),
                         caps.hasPermission());
        }
        if (newSetRollback.isPresent()) {
            assertEquals("New set rollback cap",
                         newSetRollback.get().booleanValue(),
                         caps.hasRollback());
        }
        if (newSetAuth.isPresent()) {
            assertEquals("New set auth cap",
                         newSetAuth.get().booleanValue(),
                         caps.hasAuth());
        }
    }
    
    private void testUpdateExistingLineage(final Optional<Boolean> newSetInstalledData,
                                           final Optional<Boolean> newSetSharedUid,
                                           final Optional<Boolean> newSetPermission,
                                           final Optional<Boolean> newSetRollback,
                                           final Optional<Boolean> newSetAuth)
            throws Exception {
        try {
            // first create new lineage
            addApkRotateSigner();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "OTHER_SIGNERS",
                                                        WORKER_NAME_OLD + "," +
                                                        WORKER_NAME_NEW);
            setCapsProperties(Optional.empty(), Optional.empty(), Optional.empty(),
                              Optional.empty(), Optional.empty(), Optional.empty(),
                              newSetInstalledData, newSetSharedUid,
                              newSetPermission, newSetRollback, newSetAuth);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);

            addApkSignerOld();            
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_OLD,
                                                        "DEFAULTKEY", "apk00001");
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_OLD);

            addApkSignerNew();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_NEW,
                                                        "DEFAULTKEY", "apk00002");
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_NEW);

            GenericSignRequest request = new GenericSignRequest(200, new byte[0]);
            final RemoteRequestContext context = new RemoteRequestContext();

            GenericSignResponse response =
                    (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_ID), request, context);
            byte[] lineageData = response.getProcessedData();

            final X509Certificate firstCert =
                    (X509Certificate) helper.getWorkerSession().getSignerCertificate(new WorkerIdentifier(WORKER_ID_OLD));
            
            // update for rotation, switch ApkRotateSigner to use previous next signer's
            // cert and set next signer to use a third cert
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_OLD, "DEFAULTKEY",
                                                        "apk00002");
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_NEW,
                                                        "DEFAULTKEY", "code00002");
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_OLD);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_NEW);

            // update existing lineage
            request = new GenericSignRequest(200, lineageData);
            response = (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_ID), request, context);
            lineageData = response.getProcessedData();
         
            final X509Certificate secondCert =
                    (X509Certificate) helper.getWorkerSession().getSignerCertificate(new WorkerIdentifier(WORKER_ID_OLD));
            final X509Certificate thirdCert =
                    (X509Certificate) helper.getWorkerSession().getSignerCertificate(new WorkerIdentifier(WORKER_ID_NEW));
            
            final ByteBufferDataSource dataSource =
                    new ByteBufferDataSource(ByteBuffer.wrap(lineageData));
            final SigningCertificateLineage signingCertificateLineage =
                    SigningCertificateLineage.readFromDataSource(dataSource);
            
            assertEquals("Number of signers in lineage", 3,
                         signingCertificateLineage.size());

            assertTrue("Lineage includes first cert",
                       signingCertificateLineage.isCertificateInLineage(firstCert));
            assertTrue("Lineage includes second cert",
                       signingCertificateLineage.isCertificateInLineage(secondCert));
            assertTrue("Lineage includes third cert",
                       signingCertificateLineage.isCertificateInLineage(thirdCert));
            
            final SigningCertificateLineage.SignerCapabilities thirdCaps =
                        signingCertificateLineage.getSignerCapabilities(thirdCert);
            assertUpdatedCaps(newSetInstalledData, newSetSharedUid, newSetPermission,
                       newSetRollback, newSetAuth, thirdCaps);
        } finally {
            helper.removeWorker(WORKER_ID);
            helper.removeWorker(WORKER_ID_OLD);
            helper.removeWorker(WORKER_ID_NEW);
        }
    }
    
    /**
     * Test updating an existing lineage.
     * 
     * First create a new lineage, then "rotate" the signers to use a "new new"
     * certificate and update the lineage with that, checking that all certificates
     * are included in the final lineage.
     *
     * @throws Exception 
     */
    @Test
    public void testUpdateExistingLineage() throws Exception {
        LOG.info("testUpdateExistingLineage");
        testUpdateExistingLineage(Optional.empty(), Optional.empty(),
                                  Optional.empty(), Optional.empty(),
                                  Optional.empty());
    }

    /**
     * Test updating an existing lineage.
     * 
     * First create a new lineage, then "rotate" the signers to use a "new new"
     * certificate and update the lineage with that, checking that all certificates
     * are included in the final lineage. Set installed data false of new signer.
     *
     * @throws Exception 
     */
    @Test
    public void testUpdateExistingLineageNewInstalledDataFalse() throws Exception {
        LOG.info("testUpdateExistingLineageNewInstalledDataFalse");
        testUpdateExistingLineage(Optional.of(false), Optional.empty(),
                                  Optional.empty(), Optional.empty(),
                                  Optional.empty());
    }

    /**
     * Test updating an existing lineage.
     * 
     * First create a new lineage, then "rotate" the signers to use a "new new"
     * certificate and update the lineage with that, checking that all certificates
     * are included in the final lineage. Set shared UID false of new signer.
     *
     * @throws Exception 
     */
    @Test
    public void testUpdateExistingLineageNewSharedUidFalse() throws Exception {
        LOG.info("testUpdateExistingLineageNewSharedUidFalse");
        testUpdateExistingLineage(Optional.empty(), Optional.of(false),
                                  Optional.empty(), Optional.empty(),
                                  Optional.empty());
    }

    /**
     * Test updating an existing lineage.
     * 
     * First create a new lineage, then "rotate" the signers to use a "new new"
     * certificate and update the lineage with that, checking that all certificates
     * are included in the final lineage. Set permission false of new signer.
     *
     * @throws Exception 
     */
    @Test
    public void testUpdateExistingLineageNewPermissionFalse() throws Exception {
        LOG.info("testUpdateExistingLineageNewPermissionFalse");
        testUpdateExistingLineage(Optional.empty(), Optional.empty(),
                                  Optional.of(false), Optional.empty(),
                                  Optional.empty());
    }

    /**
     * Test updating an existing lineage.
     * 
     * First create a new lineage, then "rotate" the signers to use a "new new"
     * certificate and update the lineage with that, checking that all certificates
     * are included in the final lineage. Set rollback true of new signer.
     *
     * @throws Exception 
     */
    @Test
    public void testUpdateExistingLineageNewRollbackFalse() throws Exception {
        LOG.info("testUpdateExistingLineageNewRollbackFalse");
        testUpdateExistingLineage(Optional.empty(), Optional.empty(),
                                  Optional.empty(), Optional.of(true),
                                  Optional.empty());
    }

    /**
     * Test updating an existing lineage.
     * 
     * First create a new lineage, then "rotate" the signers to use a "new new"
     * certificate and update the lineage with that, checking that all certificates
     * are included in the final lineage. Set auth false of new signer.
     *
     * @throws Exception 
     */
    @Test
    public void testUpdateExistingLineageNewAuthFalse() throws Exception {
        LOG.info("testUpdateExistingLineageNewAuthFalse");
        testUpdateExistingLineage(Optional.empty(), Optional.empty(),
                                  Optional.empty(), Optional.empty(),
                                  Optional.of(false));
    }

    /**
     * Test updating an existing lineage supplied via an existing APK.
     * 
     * First create a new lineage. Reconfigure new APK signer to set that lineage.
     * Sign an APK to use the new lineage, then "rotate" the signers to use a "new new"
     * certificate. Update lineage from signed APK, checking that all certificates
     * are included in the final lineage.
     *
     * @throws Exception 
     */
    @Test
    public void testUpdateExistingLineageFromApk() throws Exception {
        LOG.info("testUpdateExistingLineageFromApk");
        try {
            // first create new lineage
            addApkRotateSigner();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "OTHER_SIGNERS",
                                                        WORKER_NAME_OLD + "," +
                                                        WORKER_NAME_NEW);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);

            addApkSignerOld();            
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_OLD,
                                                        "DEFAULTKEY", "apk00001");
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_OLD);

            addApkSignerNew();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_NEW,
                                                        "DEFAULTKEY", "apk00002");
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_NEW,
                                                        "V1_SIGNATURE", "false");
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_NEW,
                                                        "V2_SIGNATURE", "false");
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_NEW);

            GenericSignRequest request = new GenericSignRequest(200, new byte[0]);
            final RemoteRequestContext context = new RemoteRequestContext();

            GenericSignResponse response =
                    (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_ID), request, context);
            byte[] lineageData = response.getProcessedData();

            final X509Certificate firstCert =
                    (X509Certificate) helper.getWorkerSession().getSignerCertificate(new WorkerIdentifier(WORKER_ID_OLD));

            // set lineage on new APK signer
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_NEW,
                                                        "LINEAGE_FILE_CONTENT",
                                                        Base64.toBase64String(lineageData));
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_NEW);

            // send unsigned APK to new signer to get signed APK with lineage
            request =
                    new GenericSignRequest(200, 
                                           FileUtils.readFileToByteArray(unsignedApkFile));
            response =
                    (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_ID_NEW),
                                                                 request,
                                                                 context);
            byte[] signedFile = response.getProcessedData();
            
            // update for rotation, switch ApkRotateSigner to use previous next signer's
            // cert and set next signer to use a third cert
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_OLD, "DEFAULTKEY",
                                                        "apk00002");
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_NEW,
                                                        "DEFAULTKEY", "code00002");
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_OLD);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_NEW);

            // update existing lineage
            request = new GenericSignRequest(200, signedFile);
            response = (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_ID), request, context);
            lineageData = response.getProcessedData();
         
            final X509Certificate secondCert =
                    (X509Certificate) helper.getWorkerSession().getSignerCertificate(new WorkerIdentifier(WORKER_ID_OLD));
            final X509Certificate thirdCert =
                    (X509Certificate) helper.getWorkerSession().getSignerCertificate(new WorkerIdentifier(WORKER_ID_NEW));
            
            final ByteBufferDataSource dataSource =
                    new ByteBufferDataSource(ByteBuffer.wrap(lineageData));
            final SigningCertificateLineage signingCertificateLineage =
                    SigningCertificateLineage.readFromDataSource(dataSource);
            
            assertEquals("Number of signers in lineage", 3,
                         signingCertificateLineage.size());

            assertTrue("Lineage includes first cert",
                       signingCertificateLineage.isCertificateInLineage(firstCert));
            assertTrue("Lineage includes second cert",
                       signingCertificateLineage.isCertificateInLineage(secondCert));
            assertTrue("Lineage includes third cert",
                       signingCertificateLineage.isCertificateInLineage(thirdCert));
        } finally {
            helper.removeWorker(WORKER_ID);
            helper.removeWorker(WORKER_ID_OLD);
            helper.removeWorker(WORKER_ID_NEW);
        }
    }

    
    /**
     * Test updating lineage on an APK missing lineage. Should give an
     * IllegalRequestException.
     *
     * @throws Exception 
     */
    @Test
    public void testApkMissingLineage() throws Exception {
        LOG.info("testUpdateExistingLineage");
        try {
            // first create new lineage
            addApkRotateSigner();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "OTHER_SIGNERS",
                                                        WORKER_NAME_OLD + "," +
                                                        WORKER_NAME_NEW);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);

            addApkSignerOld();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_OLD,
                                                        "DEFAULTKEY", "apk00001");
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_OLD);

            addApkSignerNew();
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_NEW,
                                                        "DEFAULTKEY", "apk00002");
            helper.getWorkerSession().reloadConfiguration(WORKER_ID_NEW);

            GenericSignRequest request =
                    new GenericSignRequest(200, FileUtils.readFileToByteArray(apkFile));
            final RemoteRequestContext context = new RemoteRequestContext();

            GenericSignResponse response =
                    (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_ID), request, context);
            fail("Should throw IllegalRequestException");
        } catch (IllegalRequestException e) {
            assertEquals("Exception message", "No lineage found in APK",
                         e.getMessage());
        } finally {
            helper.removeWorker(WORKER_ID);
            helper.removeWorker(WORKER_ID_OLD);
            helper.removeWorker(WORKER_ID_NEW);
        }
    }
}
