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
package org.signserver.module.pdfsigner;

import com.lowagie.text.DocumentException;
import com.lowagie.text.exceptions.BadPasswordException;
import com.lowagie.text.pdf.*;
import java.io.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.*;
import java.util.*;
import org.apache.commons.io.FileUtils;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.signserver.common.*;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.ejb.interfaces.ProcessSessionLocal;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertBuilderException;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.test.utils.mock.WorkerSessionMock;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.server.IServices;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;

/**
 * Unit tests for PDFSigner.
 *
 * This tests uses a mockup and does not require an running application
 * server. Tests that require that can be placed among the system tests.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class PDFSignerUnitTest extends ModulesTestCase {

    /** Logger for this class. */
    public static final Logger LOG = Logger.getLogger(PDFSignerUnitTest.class);

    /** Worker7897: Default algorithms, default hashing setting. */
    private static final int WORKER1 = 7897;
    private static final int WORKER2 = 7898;

    private static final String NAME = "NAME";
    private static final String AUTHTYPE = "AUTHTYPE";

    private static final String CRYPTOTOKEN_CLASSNAME = 
            "org.signserver.server.cryptotokens.KeystoreCryptoToken";
    private final String SAMPLE_OWNER123_PASSWORD = "owner123";
    private final String SAMPLE_USER_AAA_PASSWORD = "user\u00e5\u00e4\u00f6";
    private final String SAMPLE_OPEN123_PASSWORD = "open123";

    private final String ILLEGAL_DIGEST_FOR_DSA_MESSAGE = "Only SHA1 is permitted as digest algorithm for DSA public/private keys";

    private GlobalConfigurationSessionLocal globalConfig;
    private WorkerSessionRemote workerSession;
    private ProcessSessionLocal processSession;

    private File sampleOk;
    private File sampleRestricted;

    private File sample;
    private File sampleOpen123;
    private File sampleOpen456noRestrictions;
    private File sampleOpen123Owner123;
    private File sampleOwner123;
    private File sampleUseraao;
    private File sampleCertifiedSigningAllowed;
    private File sampleCertifiedSigningAllowed256;
    private File sampleCertifiedNoChangesAllowed;
    private File sampleCertifiedNoChangesAllowed256;
    private File sampleCertifiedFormFillingAllowed;
    private File sampleCertifiedFormFillingAllowed256;
    private File sampleSigned;
    private File sampleSignedSHA256;
//    private File sampleLowprintingOwner123;

    private JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

    public PDFSignerUnitTest() throws FileNotFoundException {
        SignServerUtil.installBCProvider();
        File home = PathUtil.getAppHome();
        sampleOk = new File(home, "res/test/ok.pdf");
        sampleRestricted = new File(home, "res/test/sample-restricted.pdf");
        sample = new File(home, "res/test/pdf/sample.pdf");
        sampleOpen123 = new File(home, "res/test/pdf/sample-open123.pdf");
        sampleOpen456noRestrictions = new File(home, "res/test/pdf/sample-open456-norestrictions.pdf");
        sampleOpen123Owner123 = new File(home, "res/test/pdf/sample-open123-owner123.pdf");
        sampleOwner123 = new File(home, "res/test/pdf/sample-owner123.pdf");
        sampleUseraao = new File(home, "res/test/pdf/sample-useraao.pdf");
        sampleCertifiedSigningAllowed = new File(home, "res/test/pdf/sample-certified-signingallowed.pdf");
        sampleCertifiedSigningAllowed256 = new File(home, "res/test/pdf/sample-certified-signingallowed256.pdf");
        sampleCertifiedNoChangesAllowed = new File(home, "res/test/pdf/sample-certified-nochangesallowed.pdf");
        sampleCertifiedNoChangesAllowed256 = new File(home, "res/test/pdf/sample-certified-nochangesallowed256.pdf");
        sampleCertifiedFormFillingAllowed = new File(home, "res/test/pdf/sample-certified-formfillingallowed.pdf");
        sampleCertifiedFormFillingAllowed256 = new File(home, "res/test/pdf/sample-certified-formfillingallowed256.pdf");
        sampleSigned = new File(home, "res/test/pdf/sample-signed.pdf");
        sampleSignedSHA256 = new File(home, "res/test/pdf/sample-signed256.pdf");
//        sampleLowprintingOwner123 = new File(home, "res/test/pdf/sample-lowprinting-owner123.pdf");
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        setupWorkers();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Test signing of a simple PDF. Mostly to test that the mockup and PDF
     * signing works before doing other tests that are expected to fail.
     * @throws Exception in case of error
     */
    public void test01signOk() throws Exception {
        ReadableData requestData = createRequestDataKeepingFile(sampleOk);
        try (CloseableWritableData responseData = createResponseData(true)) {

            final SignatureRequest request = new SignatureRequest(100,
                    requestData, responseData);

            final SignatureResponse response = (SignatureResponse)
                    processSession.process(createAdminInfo(), new WorkerIdentifier(WORKER1), request, new RequestContext(true));
            assertEquals("requestId", 100, response.getRequestID());

            Certificate signercert = response.getSignerCertificate();
            assertNotNull(signercert);

            assertTrue("data processed", responseData.toReadableData().getLength() > 0);
            assertTrue("data processed", responseData.toReadableData().getAsByteArray().length > 0);
        }
    }

    /**
     * Tries to sign a PDF with document restrictions. As no password is
     * supplied it throws an IllegalRequestException.
     * @throws Exception in case of error
     */
    public void test02SignWithRestrictionsNoPasswordSupplied() throws Exception {
        try (
                CloseableReadableData requestData = createRequestDataKeepingFile(sampleRestricted);
                CloseableWritableData responseData = createResponseData(true);
            ) {
            processSession.process(createAdminInfo(),
                    new WorkerIdentifier(WORKER1),
                    new SignatureRequest(200, requestData, responseData),
                    new RequestContext(true));
            fail("Should have thrown exception");
        } catch (IllegalRequestException ignored) {
            // OK
        }

        try (
                CloseableReadableData requestData = createRequestDataKeepingFile(sampleOpen123);
                CloseableWritableData responseData = createResponseData(true);
            ) {
            processSession.process(
                    createAdminInfo(),
                    new WorkerIdentifier(WORKER1),
                    new SignatureRequest(200, requestData, responseData),
                    new RequestContext(true));
            fail("Should have thrown exception");
        } catch (IllegalRequestException ignored) {
            // OK
        }

        try (
                CloseableReadableData requestData = createRequestDataKeepingFile(sampleOpen123Owner123);
                CloseableWritableData responseData = createResponseData(true);
            ) {
            processSession.process(
                    createAdminInfo(),
                    new WorkerIdentifier(WORKER1),
                    new SignatureRequest(200, requestData, responseData),
                    new RequestContext(true));
            fail("Should have thrown exception");
        } catch (IllegalRequestException ignored) {
            // OK
        }

        try (
                CloseableReadableData requestData = createRequestDataKeepingFile(sampleOwner123);
                CloseableWritableData responseData = createResponseData(true);
            ) {
            processSession.process(
                    createAdminInfo(),
                    new WorkerIdentifier(WORKER1),
                    new SignatureRequest(200, requestData, responseData),
                    new RequestContext());
            fail("Should have thrown exception");
        } catch (IllegalRequestException ignored) {
            // OK
        }
    }

    /**
     * Tries to sign a PDF with document restrictions. As the correct passwords
     * are supplied it should succeed.
     * @throws java.lang.Exception
     */
    public void test02SignWithRestrictionsPasswordSupplied() throws Exception {
        signProtectedPDF(sampleOpen123, "open123");
        signProtectedPDF(sampleOwner123, SAMPLE_OWNER123_PASSWORD);
        signProtectedPDF(sampleOpen123Owner123, "owner123");
        signProtectedPDF(sample, null);
        signProtectedPDF(sample, "");
        signProtectedPDF(sampleUseraao, SAMPLE_USER_AAA_PASSWORD);
    }

    /**
     * Tests the REJECT_PERMISSIONS with different values to see that the 
     * signer rejects documents with permissions not allowed.
     *
     * @throws java.lang.Exception
     */
    public void test03RejectingPermissions() throws Exception {

        // First test without any constraints
        signProtectedPDF(sampleUseraao, SAMPLE_USER_AAA_PASSWORD);

        // Test with empty list of constraints
        workerSession.setWorkerProperty(WORKER1, "REJECT_PERMISSIONS", "");
        workerSession.reloadConfiguration(WORKER1);
        signProtectedPDF(sampleUseraao, SAMPLE_USER_AAA_PASSWORD);

        // Test with unknown permission
        workerSession.setWorkerProperty(WORKER1, "REJECT_PERMISSIONS", "_NON_EXISTING_PERMISSION_");
        workerSession.reloadConfiguration(WORKER1);
        signProtectedPDF(sampleUseraao, SAMPLE_USER_AAA_PASSWORD);

        // Test with document containing an not allowed permission
        workerSession.setWorkerProperty(WORKER1, "REJECT_PERMISSIONS", "ALLOW_PRINTING");
        workerSession.reloadConfiguration(WORKER1);
        try {
            signProtectedPDF(sampleUseraao, SAMPLE_USER_AAA_PASSWORD);
            fail("Should have thrown exception");
        } catch (IllegalRequestException ok) {
            LOG.debug("OK: " + ok.getMessage());
        }

        // Test with document containing two not allowed permissions
        workerSession.setWorkerProperty(WORKER1, "REJECT_PERMISSIONS", "ALLOW_PRINTING,ALLOW_COPY");
        workerSession.reloadConfiguration(WORKER1);
        try {
            signProtectedPDF(sampleUseraao, SAMPLE_USER_AAA_PASSWORD);
            fail("Should have thrown exception");
        } catch (IllegalRequestException ok) {
            LOG.debug("OK: " + ok.getMessage());
        }

        // Test with document containing one not allowed permission and 
        // not the other disallowed permission
        workerSession.setWorkerProperty(WORKER1, "REJECT_PERMISSIONS", "ALLOW_COPY,ALLOW_MODIFY_CONTENTS");
        workerSession.reloadConfiguration(WORKER1);
        try {
            signProtectedPDF(sampleOwner123, SAMPLE_OWNER123_PASSWORD);
            fail("Should have thrown exception");
        } catch (IllegalRequestException ok) {
            LOG.debug("OK: " + ok.getMessage());
        }

        // Test with document not contianing any permissions and thus implicitly 
        // allows everything
        workerSession.setWorkerProperty(WORKER1, "REJECT_PERMISSIONS", "ALLOW_PRINTING");
        workerSession.reloadConfiguration(WORKER1);
        try {
            signProtectedPDF(sampleOk, null);
            fail("Should have thrown exception");
        } catch (IllegalRequestException ok) {
            LOG.debug("OK: " + ok.getMessage());
        }

        // Test a document where only low-res printing is allowed
        /* TODO: When found such a document
        workerSession.setWorkerProperty(WORKER1, "REJECT_PERMISSIONS", "ALLOW_PRINTING");
        workerSession.reloadConfiguration(WORKER1);
        signProtectedPDF(sampleLowprintingOwner123, SAMPLE_OWNER123_PASSWORD);
        workerSession.setWorkerProperty(WORKER1, "REJECT_PERMISSIONS", "ALLOW_DEGRADED_PRINTING");
        workerSession.reloadConfiguration(WORKER1);
        try {
            signProtectedPDF(sampleLowprintingOwner123, SAMPLE_OWNER123_PASSWORD);
            fail("Should have thrown exception");
        } catch (IllegalRequestException ok) {
            LOG.debug("OK: " + ok.getMessage());
        }*/
    }

    /**
     * Tests the property SET_PERMISSIONS by setting different values and make
     * sure they end up in the signed PDF. Also tests that when not setting 
     * the property the original permissions remain.
     *
     * @throws java.lang.Exception
     */
    public void test04SetPermissions_SHA1() throws Exception {
        try {
            // Set SHA1 as hash algorithm so the PDF will not be upgraded
            workerSession.setWorkerProperty(WORKER1, "DIGESTALGORITHM", "SHA1");
            workerSession.reloadConfiguration(WORKER1);

            doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, null, Arrays.asList("ALLOW_PRINTING", "ALLOW_MODIFY_CONTENTS", "ALLOW_COPY", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_FILL_IN", "ALLOW_SCREENREADERS", "ALLOW_ASSEMBLY", "ALLOW_DEGRADED_PRINTING"));
            doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, null, Arrays.asList("ALLOW_PRINTING", "ALLOW_MODIFY_CONTENTS", "ALLOW_COPY", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_FILL_IN", "ALLOW_ASSEMBLY", "ALLOW_DEGRADED_PRINTING"));
            doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, null, Arrays.asList( "ALLOW_MODIFY_CONTENTS", "ALLOW_COPY", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_FILL_IN", "ALLOW_ASSEMBLY", "ALLOW_DEGRADED_PRINTING"));
            doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, null, Arrays.asList( "ALLOW_COPY", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_FILL_IN", "ALLOW_ASSEMBLY", "ALLOW_DEGRADED_PRINTING"));
            doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, null, Arrays.asList( "ALLOW_COPY", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_FILL_IN", "ALLOW_DEGRADED_PRINTING"));
            doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, null, Arrays.asList( "ALLOW_COPY", "ALLOW_FILL_IN", "ALLOW_DEGRADED_PRINTING"));
            doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, null, Arrays.asList( "ALLOW_FILL_IN", "ALLOW_DEGRADED_PRINTING"));
            doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, null, Arrays.asList( "ALLOW_FILL_IN"));
            doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, null, new LinkedList<String>());

            // Without SET_PERMISSIONS the original permissions should remain
            // The sampleOwner123 originally has: ALLOW_FILL_IN,ALLOW_MODIFY_ANNOTATIONS,ALLOW_MODIFY_CONTENTS
            workerSession.removeWorkerProperty(WORKER1, "SET_PERMISSIONS");
            workerSession.reloadConfiguration(WORKER1);
            Set<String> expected = new HashSet<>(Arrays.asList("ALLOW_FILL_IN", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_MODIFY_CONTENTS"));
            Permissions actual = getPermissions(signProtectedPDF(sampleOwner123, SAMPLE_OWNER123_PASSWORD),
                    SAMPLE_OWNER123_PASSWORD.getBytes("ISO-8859-1"));
            assertEquals(expected, actual.asSet());
        } finally {
            workerSession.setWorkerProperty(WORKER1, "DIGESTALGORITHM", "SHA256");
            workerSession.reloadConfiguration(WORKER1);
        }
    }

    /**
     * Tests the property SET_PERMISSIONS by setting different values and make
     * sure they end up in the signed PDF also when the PDF version is being
     * upgraded. 
     * Also tests that existing permissions/restrictions are remaining and in
     * the case no restrictions are given then the final PDF also has no
     * restrictions.
     *
     * @throws java.lang.Exception
     */
    public void test04SetPermissions_upgradedVersion() throws Exception {
        // Test requires a PDF with version less then 1.6
        String header;
        try (BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(sampleOwner123)))) {
            header = in.readLine();
        }
        if (!"%PDF-1.4".equals(header)) {
            throw new Exception("Test expects a PDF with version 1.4 but header was \"" + header + "\"");
        }

        doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, null, Arrays.asList("ALLOW_PRINTING", "ALLOW_MODIFY_CONTENTS", "ALLOW_COPY", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_FILL_IN", "ALLOW_SCREENREADERS", "ALLOW_ASSEMBLY", "ALLOW_DEGRADED_PRINTING"));

        // Without SET_PERMISSIONS the original permissions should remain
        // The sampleOwner123 originally has: ALLOW_FILL_IN,ALLOW_MODIFY_ANNOTATIONS,ALLOW_MODIFY_CONTENTS
        workerSession.removeWorkerProperty(WORKER1, "SET_PERMISSIONS");
        workerSession.reloadConfiguration(WORKER1);
        Set<String> expected = new HashSet<>(Arrays.asList("ALLOW_FILL_IN", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_MODIFY_CONTENTS"));
        Permissions actual = getPermissions(signProtectedPDF(sampleOwner123, SAMPLE_OWNER123_PASSWORD),
                SAMPLE_OWNER123_PASSWORD.getBytes("ISO-8859-1"));
        assertEquals(expected, actual.asSet());

        // Without SET_PERMISSIONS and without restrictions the final PDF
        // should also not have any restrictions.
        // The sample originally has: cryptoMode==-1 / Permissions(0)
        workerSession.removeWorkerProperty(WORKER1, "SET_PERMISSIONS");
        workerSession.reloadConfiguration(WORKER1);
        byte[] sampleBytes = FileUtils.readFileToByteArray(this.sample);
        if (getCryptoMode(sampleBytes, null) != -1) {
            throw new Exception("sample PDF should not have any security mode set");
        }

        expected = getPermissions(sampleBytes, null).asSet();
        byte[] signedPDF = signPDF(sample);
        actual = getPermissions(signedPDF, null);
        assertEquals("permissions of PDF without restrictions", expected, actual.asSet());
        assertEquals("no security set", -1, getCryptoMode(signedPDF, null));


        // Without SET_PERMISSIONS and without restrictions the final PDF
        // should also not have any restrictions.
        // The sample originally has: cryptoMode==-1 / Permissions(0)
        workerSession.removeWorkerProperty(WORKER1, "SET_PERMISSIONS");
        workerSession.reloadConfiguration(WORKER1);
        sampleBytes = FileUtils.readFileToByteArray(this.sampleOpen456noRestrictions);
        if (getCryptoMode(sampleBytes, "open456".getBytes()) != 1) {
            throw new Exception("sampleOpen456noRestrictions PDF should have cryptoMode==1 as it has a open password specified");
        }

        expected = getPermissions(sampleBytes, "open456".getBytes()).asSet();
        LOG.info("expected: " + expected);
        signedPDF = signProtectedPDF(sampleOpen456noRestrictions, "open456");
        actual = getPermissions(signedPDF, "open456".getBytes());
        assertEquals("permissions of PDF without restrictions", expected, actual.asSet());
        assertEquals("security set", 1, getCryptoMode(signedPDF, "open456".getBytes()));
    }

    /** Tests the property SET_PERMISSIONS by setting different values and make 
     * sure they end up in the signed PDF. Also tests that when not setting 
     * the property the original permissions remain.
     * This time for documents without owner password set or with both user 
     * and owner passwords.
     *
     * @throws java.lang.Exception
     */
    public void test04SetPermissionsWithoutOwner() throws Exception {
        doTestSetPermissions(WORKER1, sample, null, null, Arrays.asList("ALLOW_PRINTING", "ALLOW_MODIFY_CONTENTS", "ALLOW_COPY", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_FILL_IN", "ALLOW_SCREENREADERS", "ALLOW_ASSEMBLY", "ALLOW_DEGRADED_PRINTING"));
        doTestSetPermissions(WORKER1, sampleOpen123, null, SAMPLE_OPEN123_PASSWORD, Arrays.asList("ALLOW_PRINTING", "ALLOW_MODIFY_CONTENTS", "ALLOW_COPY", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_FILL_IN", "ALLOW_ASSEMBLY", "ALLOW_DEGRADED_PRINTING"));
        doTestSetPermissions(WORKER1, sampleOpen123Owner123, SAMPLE_OWNER123_PASSWORD, SAMPLE_OPEN123_PASSWORD, Arrays.asList( "ALLOW_MODIFY_CONTENTS", "ALLOW_COPY", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_FILL_IN", "ALLOW_ASSEMBLY", "ALLOW_DEGRADED_PRINTING"));
    }

    private void doTestSetPermissions(int workerId, File pdf, String ownerPassword, String userPassword, Collection<String> permissions) throws Exception {
        Set<String> expected = new HashSet<>(permissions);
        workerSession.setWorkerProperty(workerId, "SET_PERMISSIONS", toString(expected, ","));
        workerSession.reloadConfiguration(workerId);
        String password = ownerPassword == null ? userPassword : ownerPassword;
        byte[] pdfbytes = signProtectedPDF(pdf, password);
        Permissions actual = getPermissions(pdfbytes,
                userPassword == null ? (ownerPassword == null ? null : ownerPassword.getBytes("ISO-8859-1")) : userPassword.getBytes("ISO-8859-1"));
        assertEquals(expected, actual.asSet());

        // Check that user password hasn't become the owner password (unless it already were)
        if (ownerPassword != null && userPassword != null && !ownerPassword.equals(userPassword)) {
            assertUserNotOwnerPassword(pdfbytes, userPassword);
        }

        // Check that the document is protected by an permissions password
        PdfReader reader = new PdfReader(pdfbytes, userPassword == null ? null : userPassword.getBytes("ISO-8859-1"));
        assertFalse("Should not be openned with full permissions",
                reader.isOpenedWithFullPermissions());
    }

    private byte[] doTestRemovePermissions(int workerId, File pdf, String ownerPassword, String userPassword, Collection<String> removePermissions, Collection<String> expected) throws Exception {
        Set<String> expectedSet = new HashSet<>(expected);
        workerSession.setWorkerProperty(workerId, "REMOVE_PERMISSIONS", toString(removePermissions, ","));
        workerSession.reloadConfiguration(workerId);
        byte[] pdfbytes = signProtectedPDF(pdf, ownerPassword == null ? userPassword : ownerPassword);
        Permissions actual = getPermissions(pdfbytes, ownerPassword == null ? (userPassword == null ? null : userPassword.getBytes("ISO-8859-1")) : ownerPassword.getBytes("ISO-8859-1"));
        assertEquals(expectedSet, actual.asSet());

        // Check that user password hasn't become the owner password (unless it already were)
        if (ownerPassword != null && userPassword != null && !ownerPassword.equals(userPassword)) {
            assertUserNotOwnerPassword(pdfbytes, userPassword);
        }

        // If some permissions are removed, check that the document is protected by an permissions password
        if (!removePermissions.isEmpty()) {
            PdfReader reader = new PdfReader(pdfbytes, userPassword == null ? null : userPassword.getBytes("ISO-8859-1"));
            assertFalse("Should not be openned with full permissions",
                    reader.isOpenedWithFullPermissions());
        }

        return pdfbytes;
    }

    private static String toString(Collection<String> collection, String separator) {
        StringBuilder buff = new StringBuilder();
        for (String s : collection) {
            buff.append(s).append(separator);
        }
        return buff.toString();
    }

    /**
     * Tests the REMOVE_PERMISSIONS property by setting different values for
     * what to remove and check that they were removed from the signed PDF.
     *
     * @throws java.lang.Exception
     */
    public void test04RemovePermissions() throws Exception {
        // The sampleOwner123 originally has: ALLOW_FILL_IN,ALLOW_MODIFY_ANNOTATIONS,ALLOW_MODIFY_CONTENTS
        doTestRemovePermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, null, Arrays.asList("ALLOW_FILL_IN"), Arrays.asList("ALLOW_MODIFY_ANNOTATIONS", "ALLOW_MODIFY_CONTENTS"));
        doTestRemovePermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, null, Arrays.asList("ALLOW_MODIFY_ANNOTATIONS"), Arrays.asList("ALLOW_FILL_IN", "ALLOW_MODIFY_CONTENTS"));
        doTestRemovePermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, null, Arrays.asList("ALLOW_MODIFY_CONTENTS"), Arrays.asList("ALLOW_FILL_IN", "ALLOW_MODIFY_ANNOTATIONS"));

        doTestRemovePermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, null, Arrays.asList("ALLOW_MODIFY_ANNOTATIONS", "ALLOW_MODIFY_CONTENTS"), Arrays.asList("ALLOW_FILL_IN"));
        doTestRemovePermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, null, Arrays.asList("ALLOW_FILL_IN", "ALLOW_MODIFY_CONTENTS"), Arrays.asList("ALLOW_MODIFY_ANNOTATIONS"));
        doTestRemovePermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, null, Arrays.asList("ALLOW_FILL_IN", "ALLOW_MODIFY_ANNOTATIONS"), Arrays.asList("ALLOW_MODIFY_CONTENTS"));
    }

    public void test04RemovePermissionsWithoutOwner() throws Exception {

        // Removing any permissions should protected the document even 
        // if it did not contain the permission before but was unprotected
        // (unprotected means all permissions)
        Collection<String> anyPermissions = Arrays.asList("ALLOW_FILL_IN");

        // sample has Permissions(0)
        byte[] pdfbytes = doTestRemovePermissions(WORKER1, sample, null, null, anyPermissions, new LinkedList<String>());
        assertUserNotOwnerPassword(pdfbytes, null);

        // sampleOpen123 has Permissions(-1028)[ALLOW_FILL_IN, ALLOW_MODIFY_ANNOTATIONS, ALLOW_DEGRADED_PRINTING, ALLOW_SCREENREADERS, ALLOW_COPY, ALLOW_PRINTING, ALLOW_MODIFY_CONTENTS]
        Collection<String> anyPermissionsRemoved = Arrays.asList("ALLOW_MODIFY_ANNOTATIONS", "ALLOW_DEGRADED_PRINTING", "ALLOW_SCREENREADERS", "ALLOW_COPY", "ALLOW_PRINTING", "ALLOW_MODIFY_CONTENTS");
        pdfbytes = doTestRemovePermissions(WORKER1, sampleOpen123, null, SAMPLE_OPEN123_PASSWORD, anyPermissions, anyPermissionsRemoved);
        assertUserNotOwnerPassword(pdfbytes, SAMPLE_OPEN123_PASSWORD);
    }

    /**
     * Tests illegal configuration: specifying mutually exclusive properties.
     */
    public void test04SetAndRemovePermissions() throws Exception {
        workerSession.setWorkerProperty(WORKER1, "SET_PERMISSIONS", "ALLOW_COPY");
        workerSession.setWorkerProperty(WORKER1, "REMOVE_PERMISSIONS", "ALLOW_FILL_IN");
        workerSession.reloadConfiguration(WORKER1);
        try {
            signProtectedPDF(sampleOwner123, SAMPLE_OWNER123_PASSWORD);
            fail("Should have thrown exception");
        } catch (SignServerException ok) {
            LOG.debug("OK: " + ok.getMessage());
        }
    }

    /**
     * Tests that rejecting permissions still works even do we set permissions
     * explicitly.
     *
     * @throws java.lang.Exception
     */
    public void test05SetAndRejectPermissions() throws Exception {
        // Setting a permission we then reject. Not so clever :)
        workerSession.setWorkerProperty(WORKER1, "SET_PERMISSIONS", "ALLOW_MODIFY_CONTENTS,ALLOW_COPY");
        workerSession.setWorkerProperty(WORKER1, "REJECT_PERMISSIONS", "ALLOW_COPY");
        workerSession.reloadConfiguration(WORKER1);
        try {
            signProtectedPDF(sampleOwner123, SAMPLE_OWNER123_PASSWORD);
            fail("Should have thrown exception");
        } catch (IllegalRequestException ok) {
            LOG.debug("OK: " + ok.getMessage());
        }
    }

    /**
     * Tests that even do we remove some permission we will still check for
     * permissions to reject. But if we remove all rejected the document is ok.
     *
     * @throws java.lang.Exception
     */
    public void test06RemoveAndRejectPermissions() throws Exception {
        // Remove a permissions but still the document contains a permission we reject
        workerSession.setWorkerProperty(WORKER1, "REMOVE_PERMISSIONS", "ALLOW_MODIFY_CONTENTS");
        workerSession.setWorkerProperty(WORKER1, "REJECT_PERMISSIONS", "ALLOW_FILL_IN");
        workerSession.reloadConfiguration(WORKER1);
        try {
            signProtectedPDF(sampleOwner123, SAMPLE_OWNER123_PASSWORD);
            fail("Should have thrown exception");
        } catch (IllegalRequestException ok) {
            LOG.debug("OK: " + ok.getMessage());
        }

        // Remove the permission we reject
        workerSession.setWorkerProperty(WORKER1, "REMOVE_PERMISSIONS", "ALLOW_FILL_IN");
        workerSession.reloadConfiguration(WORKER1);
        signProtectedPDF(sampleOwner123, SAMPLE_OWNER123_PASSWORD);
    }

    /**
     * Tests that it is possible also to change the permissions on a document
     * not previously protected by any password.
     *
     * @throws java.lang.Exception
     */
    public void test07ChangePermissionOfUnprotectedDocument() throws Exception {
        doTestSetPermissions(WORKER1, sampleOk, null, null, Arrays.asList( "ALLOW_FILL_IN", "ALLOW_DEGRADED_PRINTING"));
    }

    /**
     * Test helper method for asserting that a certain owner password is really
     * set.
     *
     * @throws java.lang.Exception
     */
    public void test08assertOwnerPassword() throws Exception {
        try {
            assertOwnerPassword(readFile(sampleOpen123Owner123), "open123");
            fail("Should have thrown exception as it was not openned with owner password");
        } catch (IOException ok) { // NOPMD
            // OK
        }
        try {
            assertOwnerPassword(readFile(sampleOk), "open123a");
            fail("Should have thrown exception as the password was not needed");
        } catch (IOException ok) { // NOPMD
            // OK
        }
        assertOwnerPassword(readFile(sampleOpen123Owner123), SAMPLE_OWNER123_PASSWORD);
    }

    /**
     * Tests the worker property SET_OWNERPASSWORD with documents containing
     * different password types.
     *
     * @throws java.lang.Exception
     */
    public void test09SetOwnerPassword() throws Exception {
        // Set owner password on a document that does not have any password
        String ownerPassword1 = "newownerpassword%%_1";
        workerSession.setWorkerProperty(WORKER1, "SET_OWNERPASSWORD", ownerPassword1);
        workerSession.reloadConfiguration(WORKER1);
        byte[] pdf1 = signProtectedPDF(sampleOk, null);
        assertOwnerPassword(pdf1, ownerPassword1);

        // Set owner password on a document that already has a user password
        // The user password should still be the same
        String ownerPassword2 = "newownerpassword%%_2";
        workerSession.setWorkerProperty(WORKER1, "SET_OWNERPASSWORD", ownerPassword2);
        workerSession.reloadConfiguration(WORKER1);
        byte[] pdf2 = signProtectedPDF(sampleOpen123, "open123");
        assertOwnerPassword(pdf2, ownerPassword2);
        assertUserPassword(pdf2, "open123");

        // Set owner password on a document that already has a user and owner password
        // The user password should still be the same
        String ownerPassword3 = "newownerpassword%%_3";
        workerSession.setWorkerProperty(WORKER1, "SET_OWNERPASSWORD", ownerPassword3);
        workerSession.reloadConfiguration(WORKER1);
        byte[] pdf3 = signProtectedPDF(sampleOpen123Owner123, "owner123");
        assertOwnerPassword(pdf3, ownerPassword3);
        assertUserPassword(pdf3, "open123");

        // Set owner password on a document that already has an owner password
        // The user password should still not be needed
        String ownerPassword4 = "newownerpassword%%_4";
        workerSession.setWorkerProperty(WORKER1, "SET_OWNERPASSWORD", ownerPassword4);
        workerSession.reloadConfiguration(WORKER1);
        byte[] pdf4 = signProtectedPDF(sampleOwner123, "owner123");
        assertOwnerPassword(pdf4, ownerPassword4);
        assertUserPassword(pdf4, "");
    }

    /**
     * Tests that it is possible to sign a certified document which allows
     * signing and not one the does not.
     *
     * @throws java.lang.Exception
     */
    public void test10SignCertifiedDocument_SHA1() throws Exception {
        try {
            // Note: We can not upgrade a document that is already signed so as
            // sampleSigned was using SHA1 we need to continue using it
            workerSession.setWorkerProperty(WORKER1, "DIGESTALGORITHM", "SHA1");
            workerSession.reloadConfiguration(WORKER1);

            signPDF(sampleCertifiedSigningAllowed);
            try {
                signPDF(sampleCertifiedNoChangesAllowed);
                fail("Should not be possible to sign a certified document with NO_CHANGES_ALLOWED");
            } catch (IllegalRequestException ok) {
                LOG.debug("ok: " + ok.getMessage());
            }
            try {
                signPDF(sampleCertifiedFormFillingAllowed);
                fail("Should not be possible to sign a certified document with FORM_FILLING");
            } catch (IllegalRequestException ok) {
                LOG.debug("ok: " + ok.getMessage());
            }
        } finally {
            workerSession.setWorkerProperty(WORKER1, "DIGESTALGORITHM", "SHA256");
            workerSession.reloadConfiguration(WORKER1);
        }
    }

    /**
     * Tests that it is possible to sign a certified document which allows
     * signing and not one the does not.
     *
     * @throws java.lang.Exception
     */
    public void test10SignCertifiedDocument() throws Exception {
        signPDF(sampleCertifiedSigningAllowed256);
        try {
            signPDF(sampleCertifiedNoChangesAllowed256);
            fail("Should not be possible to sign a certified document with NO_CHANGES_ALLOWED");
        } catch (IllegalRequestException ok) {
            LOG.debug("ok: " + ok.getMessage());
        }
        try {
            signPDF(sampleCertifiedFormFillingAllowed256);
            fail("Should not be possible to sign a certified document with FORM_FILLING");
        } catch (IllegalRequestException ok) {
            LOG.debug("ok: " + ok.getMessage());
        }
    }

    /**
     * Tests that it is possible to certify a document that already is signed.
     *
     * @throws java.lang.Exception
     */
    public void test11CertifySignedDocument_SHA1() throws Exception {
        try {
            // Note: We can not upgrade a document that is already signed so as
            // sampleSigned was using SHA1 we need to continue using it
            workerSession.setWorkerProperty(WORKER1, "DIGESTALGORITHM", "SHA1");
            workerSession.reloadConfiguration(WORKER1);

            workerSession.setWorkerProperty(WORKER1, "CERTIFICATION_LEVEL", "FORM_FILLING");
            workerSession.reloadConfiguration(WORKER1);
            signPDF(sampleSigned);

            workerSession.setWorkerProperty(WORKER1, "CERTIFICATION_LEVEL", "FORM_FILLING_AND_ANNOTATIONS");
            workerSession.reloadConfiguration(WORKER1);
            signPDF(sampleSigned);

            workerSession.setWorkerProperty(WORKER1, "CERTIFICATION_LEVEL", "NO_CHANGES_ALLOWED");
            workerSession.reloadConfiguration(WORKER1);
            signPDF(sampleSigned);
        } finally {
            workerSession.setWorkerProperty(WORKER1, "DIGESTALGORITHM", "SHA256");
            workerSession.reloadConfiguration(WORKER1);
        }
    }

    /**
     * Tests that it is possible to certify a document that already is signed.
     *
     * @throws java.lang.Exception
     */
    public void test11CertifySignedDocument_SHA256() throws Exception {
        workerSession.setWorkerProperty(WORKER1, "CERTIFICATION_LEVEL", "FORM_FILLING");
        workerSession.reloadConfiguration(WORKER1);
        signPDF(sampleSignedSHA256);

        workerSession.setWorkerProperty(WORKER1, "CERTIFICATION_LEVEL", "FORM_FILLING_AND_ANNOTATIONS");
        workerSession.reloadConfiguration(WORKER1);
        signPDF(sampleSignedSHA256);

        workerSession.setWorkerProperty(WORKER1, "CERTIFICATION_LEVEL", "NO_CHANGES_ALLOWED");
        workerSession.reloadConfiguration(WORKER1);
        signPDF(sampleSignedSHA256);
    }

    /**
     * Tests that it is possible to sign an already signed document.
     *
     * @throws java.lang.Exception
     */
    public void test12SignSignedDocument_SHA1() throws Exception {
        try {
            // Note: We can not upgrade a document that is already signed so as
            // sampleSigned was using SHA1 we need to continue using it
            workerSession.setWorkerProperty(WORKER1, "DIGESTALGORITHM", "SHA1");
            workerSession.reloadConfiguration(WORKER1);

            signPDF(sampleSigned);
        } finally {
            workerSession.setWorkerProperty(WORKER1, "DIGESTALGORITHM", "SHA256");
            workerSession.reloadConfiguration(WORKER1);
        }
    }

    /**
     * Tests that it is possible to sign an already signed document.
     *
     * @throws java.lang.Exception
     */
    public void test12SignSignedDocument_SHA256() throws Exception {
        signPDF(sampleSignedSHA256);
    }

    /**
     * Tests that it is not possible to certify an already certified document.
     *
     * @throws java.lang.Exception
     */
    public void test13CertifyCertifiedDocument() throws Exception {
        workerSession.setWorkerProperty(WORKER1, "CERTIFICATION_LEVEL", "FORM_FILLING");
        workerSession.reloadConfiguration(WORKER1);
        try {
            signPDF(sampleCertifiedNoChangesAllowed);
            fail("Should not be possible to certify a certified document");
        } catch (IllegalRequestException ok) {
            LOG.debug("ok: " + ok.getMessage());
        }
        try {
            signPDF(sampleCertifiedFormFillingAllowed);
            fail("Should not be possible to sign a certified document");
        } catch (IllegalRequestException ok) {
            LOG.debug("ok: " + ok.getMessage());
        }
        try {
            signPDF(sampleCertifiedSigningAllowed);
            fail("Should not be possible to sign a certified document");
        } catch (IllegalRequestException ok) {
            LOG.debug("ok: " + ok.getMessage());
        }
    }

    /**
     * Tests that our assumption that an increase of n bytes in a certificate
     * does not lead to more than an increase of n bytes in the PKCS#7 structure.
     *
     * This should never fail unless we upgrade BouncyCastle and the behavior
     * changes.
     *
     * @throws java.lang.Exception
     */
    public void test14EstimatedP7Size_increaseCertSize() throws Exception {
        final int somethingLargeEnough = 31000;
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(1024);
        KeyPair signerKeyPair = CryptoUtils.generateRSA(1024);
        PrivateKey signerPrivKey = signerKeyPair.getPrivate();
        byte[] extensionBytes = new byte[0];
        int referenceIssuerCertSize;
        int referenceSize;
        int actualP7Size;

        
        // Create initial certificates
        Certificate issuerCert = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(issuerKeyPair.getPublic()).setSubject("CN=Issuer1").setIssuer("CN=Issuer1").addExtension(new CertExt(new ASN1ObjectIdentifier("1.2.3.4"), false, new DERBitString(extensionBytes))).build());
        referenceIssuerCertSize = issuerCert.getEncoded().length;
        Certificate signerCert = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(signerKeyPair.getPublic()).setSubject("CN=Signer").setIssuer("CN=Issuer1").build());

        // We will only variate the issuer certificate size
        // so the other parameters are not important for this test
        CRL[] crlList = new CRL[0];
        MockedTSAClient tsc = new MockedTSAClient(1234);
        byte[] ocsp = "OOOOOOOO".getBytes();

        // Test 1: First test is the reference test
        Certificate[] certChain = new Certificate[] {signerCert, issuerCert};
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        referenceSize = actualP7Size;
        LOG.debug("referenceSize: " + actualP7Size);
        LOG.debug("referenceIssuerCertSize: " + referenceIssuerCertSize);

        // Test 2: Increase the size of the certificate with 1 byte and test
        // that the final P7 does not increases with more than 1 byte
        extensionBytes = new byte[1];
        issuerCert = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(issuerKeyPair.getPublic()).setSubject("CN=Issuer1").setIssuer("CN=Issuer1").addExtension(new CertExt(new ASN1ObjectIdentifier("1.2.3.4"), false, new DERBitString(extensionBytes))).build());
        certChain = new Certificate[] {signerCert, issuerCert};
        if (issuerCert.getEncoded().length != referenceIssuerCertSize + 1) {
            throw new Exception("The test should have increased the certificate size by 1 byte");
        }
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        assertEquals("new size 1 byte larger", referenceSize + 1, actualP7Size);

        // Test 2: Increase the size of the certificate with 37 bytes and test
        // that the final P7 does not increases with more than 37 bytes
        extensionBytes = new byte[37];
        issuerCert = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(issuerKeyPair.getPublic()).setSubject("CN=Issuer1").setIssuer("CN=Issuer1").addExtension(new CertExt(new ASN1ObjectIdentifier("1.2.3.4"), false, new DERBitString(extensionBytes))).build());
        certChain = new Certificate[] {signerCert, issuerCert};
        if (issuerCert.getEncoded().length != referenceIssuerCertSize + 37) {
            throw new Exception("The test should have increased the certificate size by 37 bytes but was: " + issuerCert.getEncoded().length);
        }
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        assertEquals("new size 37 bytes larger", referenceSize + 37, actualP7Size);

        
        // Test 2: Increase the size of the certificate with at least 10000 bytes and test
        // that the final P7 does not increases more than the certificate
        // (it turned out that increasing the certificate with 10000 bytes actually made it even larger, 
        //  however that is not important in this case)
        extensionBytes = new byte[10000];
        issuerCert = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(issuerKeyPair.getPublic()).setSubject("CN=Issuer1").setIssuer("CN=Issuer1").addExtension(new CertExt(new ASN1ObjectIdentifier("1.2.3.4"), false, new DERBitString(extensionBytes))).build());
        certChain = new Certificate[] {signerCert, issuerCert};
        int certIncrease = issuerCert.getEncoded().length - referenceIssuerCertSize;
        LOG.debug("increased certificate size with: " + certIncrease);
        if (certIncrease < 10000) {
            throw new Exception("The test should have increased the certificate with at least 10000 bytes but was: " + issuerCert.getEncoded().length);
        }
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        assertEquals("new larger size", referenceSize + certIncrease, actualP7Size);
        referenceSize = actualP7Size;

        // Test 3: Increase the size of the certificate with at least 30123 bytes and test
        // that the final P7 does not increases more than the certificate
        extensionBytes = new byte[30123];
        issuerCert = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(issuerKeyPair.getPublic()).setSubject("CN=Issuer1").setIssuer("CN=Issuer1").addExtension(new CertExt(new ASN1ObjectIdentifier("1.2.3.4"), false, new DERBitString(extensionBytes))).build());
        certChain = new Certificate[] {signerCert, issuerCert};
        certIncrease = issuerCert.getEncoded().length - referenceIssuerCertSize;
        LOG.debug("increased certificate size with: " + certIncrease);
        if (certIncrease < 30123) {
            throw new Exception("The test should have increased the certificate with at least 30123 bytes but was: " + issuerCert.getEncoded().length);
        }
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        // It turns out that the P7 might use less size than the increase in the certificate
        assertTrue("new larger size", referenceSize + certIncrease >= actualP7Size);
        //referenceSize = actualP7Size;        
    }

    /**
     * Tests that our assumption that an increase of n bytes in a time-stamp response 
     * does not lead to more than an increase of n bytes in the PKCS#7 structure.
     *
     * This should never fail unless we upgrade BouncyCastle and the behavior
     * changes.
     *
     * @throws java.lang.Exception
     */
    public void test14EstimatedP7Size_increaseTSRSize() throws Exception {
        final int somethingLargeEnough = 31000;
        KeyPair signerKeyPair = CryptoUtils.generateRSA(1024);
        PrivateKey signerPrivKey = signerKeyPair.getPrivate();
        int referenceTSRSize;
        int referenceSize;
        int actualP7Size;

        // We will only variate the Time-stamp response size
        // so the other parameters are not important for this test
        Certificate[] certChain = new Certificate[] {converter.getCertificate(new CertBuilder().build())};
        CRL[] crlList = new CRL[0];
        byte[] ocsp = "OOOOOOOO".getBytes();

        // Test 1: First test is the reference test
        MockedTSAClient tsc = new MockedTSAClient(0);

        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        referenceSize = actualP7Size;
        referenceTSRSize = tsc.getTimeStampToken().length;
        LOG.debug("referenceSize: " + actualP7Size);
        LOG.debug("referenceTSRSize: " + referenceTSRSize);

        // Test 2: Increase the size of the TSR with 1 byte and test
        // that the final P7 does not increases with more than 1 byte
        tsc = new MockedTSAClient(1);
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        assertEquals("new size 1 byte larger", referenceSize + 1, actualP7Size);

        // Test 2: Increase the size of the certificate with 37 bytes and test
        // that the final P7 does not increases with more than 37 bytes
        tsc = new MockedTSAClient(37);
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        assertEquals("new size 37 bytes larger", referenceSize + 37, actualP7Size);

        
        // Test 2: Increase the size of the certificate with at least 10000 bytes and test
        // that the final P7 does not increases more than the certificate
        // (it turned out that increasing the TSR with 10000 bytes actually made it even larger, 
        //  however that is not important in this case)
        tsc = new MockedTSAClient(10000);
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        int tsrIncrease = tsc.getTokenSizeEstimate() - referenceTSRSize;
        LOG.debug("increased certificate size with: " + tsrIncrease);
        // It turns out that the P7 might use less size than the increase in the TSR size
        assertTrue("new larger size", referenceSize + tsrIncrease >= actualP7Size);
        referenceSize = actualP7Size;

        // Test 3: Increase the size of the certificate with at least 30123 bytes and test
        // that the final P7 does not increases more than the certificate
        tsc = new MockedTSAClient(30123);
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        tsrIncrease = tsc.getTokenSizeEstimate() - referenceTSRSize;
        // It turns out that the P7 might use less size than the increase in the TSR size
        assertTrue("new larger size", referenceSize + tsrIncrease >= actualP7Size);
        //referenceSize = actualP7Size;        
    }

    /**
     * Tests that our assumption that an increase of n bytes in a certificate
     * does not lead to more than an increase of n+X bytes in the PKCS#7 structure 
     * where X seems to be 1 extra byte that could be needed.
     *
     * This should never fail unless we upgrade BouncyCastle and the behavior
     * changes.
     *
     * @throws java.lang.Exception
     */
    public void test14EstimatedP7Size_increaseCRLSize() throws Exception {
        final int extraSpace = 1;

        final int somethingLargeEnough = 31000;
        KeyPair signerKeyPair = CryptoUtils.generateRSA(1024);
        PrivateKey signerPrivKey = signerKeyPair.getPrivate();
        byte[] extensionBytes;
        final int referenceCRLSize;
        int referenceSize;
        int actualP7Size;

        
        // Create initial certificates
        Certificate[] certChain = new Certificate[] {converter.getCertificate(new CertBuilder().build())};

        // We will only variate the issuer certificate size
        // so the other parameters are not important for this test
        MockedTSAClient tsc = new MockedTSAClient(1234);
        byte[] ocsp = "OOOOOOOO".getBytes();

        // Test 1: First test is the reference test
        CRL[] crlList = new CRL[]{createCRL(signerPrivKey, new byte[0])};
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        referenceSize = actualP7Size;
        referenceCRLSize = ((X509CRL) crlList[0]).getEncoded().length;
        LOG.debug("referenceSize: " + actualP7Size);
        LOG.debug("referenceCRLSize: " + referenceCRLSize);

        // Test 2: Increase the size of the CRL with 1 byte and test
        // that the final P7 does not increases with more than 1 byte
        extensionBytes = new byte[1];
        crlList = new CRL[]{createCRL(signerPrivKey, extensionBytes)};
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        assertEquals("new size 1 byte larger", referenceSize + 1, actualP7Size);

        // Test 2: Increase the size of the certificate with 37 bytes and test
        // that the final P7 does not increases with more than 37 bytes
        extensionBytes = new byte[37];
        crlList = new CRL[]{createCRL(signerPrivKey, extensionBytes)};
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        assertTrue("new size 37 bytes larger", actualP7Size <= referenceSize + 37 + extraSpace);

        
        // Test 2: Increase the size of the certificate with at least 10000 bytes and test
        // that the final P7 does not increases more than the certificate
        // (it turned out that increasing the certificate with 10000 bytes actually made it even larger, 
        //  however that is not important in this case)
        extensionBytes = new byte[10000];
        crlList = new CRL[]{createCRL(signerPrivKey, extensionBytes)};
        int certIncrease = ((X509CRL) crlList[0]).getEncoded().length - referenceCRLSize;
        LOG.debug("increased CRL size with: " + certIncrease);
        if (certIncrease < 10000) {
            throw new Exception("The test should have increased the certificate with at least 10000 bytes but was: " + certIncrease);
        }
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        assertEquals("new larger size", referenceSize + certIncrease, actualP7Size);
        referenceSize = actualP7Size;

        // Test 3: Increase the size of the certificate with at least 30123 bytes and test
        // that the final P7 does not increases more than the certificate
        extensionBytes = new byte[30123];
        crlList = new CRL[]{createCRL(signerPrivKey, extensionBytes)};
        certIncrease = ((X509CRL) crlList[0]).getEncoded().length - referenceCRLSize;
        LOG.debug("increased CRL size with: " + certIncrease);
        if (certIncrease < 30123) {
            throw new Exception("The test should have increased the certificate with at least 30123 bytes but was: " + certIncrease);
        }
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        // It turns out that the P7 might use less size than the increase in the certificate
        assertTrue("new larger size", referenceSize + certIncrease >= actualP7Size);
        //referenceSize = actualP7Size;        
    }

    private X509CRL createCRL(PrivateKey caCrlPrivKey, byte[] data) throws Exception {
        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(new X500Name("CN=CRL Issuer"), new Date());
        crlGen.addCRLEntry(BigInteger.ONE, new Date(), CRLReason.privilegeWithdrawn);
        crlGen.addExtension(new ASN1ObjectIdentifier("1.2.3.4"), false, new DERBitString(data));
        X509CRLHolder crl = crlGen.build(new JcaContentSignerBuilder("SHA1withRSA").build(caCrlPrivKey));
        return new JcaX509CRLConverter().getCRL(crl);
    }

    private int sumCertSizes(Certificate[] certs) throws CertificateEncodingException {
        return sumCertSizes(certs, 0);
    }

    private int sumCertSizes(Certificate[] certs, int offset) throws CertificateEncodingException {
        int result = 0;
        for (int i = offset; i < certs.length; i++) {
            result += certs[i].getEncoded().length;
        }
        return result;
    }

    private int sumCRLSizes(CRL[] crls) throws CRLException {
        return sumCRLSizes(crls, 0);
    }

    private int sumCRLSizes(CRL[] crls, int offset) throws CRLException {
        int result = 0;
        for (int i = offset; i < crls.length; i++) {
            result += ((X509CRL) crls[i]).getEncoded().length;
        }
        return result;
    }

    /**
     * Tests that our assumption that adding an additional certificate does not
     * increase the size with more than the size of the certificate.
     *
     * This should never fail unless we upgrade BouncyCastle and the behavior
     * changes.
     *
     * @throws java.lang.Exception
     */
    public void test14EstimatedP7Size_increaseNumCerts() throws Exception {
        final int somethingLargeEnough = 31000;
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(1024);
        KeyPair signerKeyPair = CryptoUtils.generateRSA(1024);
        PrivateKey signerPrivKey = signerKeyPair.getPrivate();
        byte[] extensionBytes = new byte[0];
        int referenceIssuerCertSize;
        int referenceSize;
        int actualP7Size;

        
        // Create initial certificates
        Certificate signerCert = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(signerKeyPair.getPublic()).setSubject("CN=Signer").setIssuer("CN=Issuer1").build());
        Certificate[] allCerts = new Certificate[50];
        allCerts[0] = signerCert;
        for (int i = 1; i < 50; i++) {
            allCerts[i] = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(issuerKeyPair.getPublic()).setSubject("CN=Issuer" + i).setIssuer("CN=Issuer" + i).addExtension(new CertExt(new ASN1ObjectIdentifier("1.2.3.4"), false, new DERBitString(extensionBytes))).build());
        }

        // We will only variate the number of issuer certificates
        // so the other parameters are not important for this test
        CRL[] crlList = new CRL[0];
        MockedTSAClient tsc = new MockedTSAClient(1234);
        byte[] ocsp = "OOOOOOOO".getBytes();

        // Test 1: First test is the reference test
        Certificate[] certChain = new Certificate[2];
        System.arraycopy(allCerts, 0, certChain, 0, 2); // 2 certificates
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        LOG.debug("actualP7Size=" + actualP7Size + ", sumCertSizes=" + sumCertSizes(certChain));
        referenceSize = actualP7Size;
        referenceIssuerCertSize = sumCertSizes(certChain);
        LOG.debug("referenceSize: " + actualP7Size);
        LOG.debug("referenceIssuerCertSize: " + referenceIssuerCertSize);

        // Test 2: Increase the size of the certificate chain with 1 and test
        // that the final P7 does not increases with more than the size of the certificate
        certChain = new Certificate[3];
        System.arraycopy(allCerts, 0, certChain, 0, 3); // 3 certificates
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        int diff = actualP7Size - referenceSize - sumCertSizes(certChain, 2);
        LOG.debug("actualP7Size=" + actualP7Size + ", sumCertSizes=" + sumCertSizes(certChain));
        assertEquals("no extra added for each certificate", 0, diff);

        // Test 3: Increase the size of the certificate chain with 2 and test
        // that the final P7 does not increases with more than the size of the certificates
        certChain = new Certificate[4];
        System.arraycopy(allCerts, 0, certChain, 0, 4); // 4 certificates
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        diff = actualP7Size - referenceSize - sumCertSizes(certChain, 2);
        LOG.debug("actualP7Size=" + actualP7Size + ", sumCertSizes=" + sumCertSizes(certChain));
        assertEquals("no extra added for each certificate", 0, diff);

        // Test 4: Increase the size of the certificate chain with 49 and test
        // that the final P7 does not increases with more than the size of the certificates
        certChain = new Certificate[50];
        System.arraycopy(allCerts, 0, certChain, 0, 50); // 50 certificates
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        diff = actualP7Size - referenceSize - sumCertSizes(certChain, 2);
        LOG.debug("actualP7Size=" + actualP7Size + ", sumCertSizes=" + sumCertSizes(certChain));
        assertEquals("no extra added for each certificate", 0, diff);
    }

    /**
     * Tests that our assumption that adding an additional CRL does not
     * increase the size with more than the size of the CRL.
     *
     * This should never fail unless we upgrade BouncyCastle and the behavior
     * changes.
     *
     * @throws java.lang.Exception
     */
    public void test14EstimatedP7Size_increaseNumCRLs() throws Exception {
        final int somethingLargeEnough = 31000;
        KeyPair signerKeyPair = CryptoUtils.generateRSA(1024);
        PrivateKey signerPrivKey = signerKeyPair.getPrivate();
        int referenceCRLSize;
        int referenceSize;
        int actualP7Size;
        CRL[] crlList;

        // Create initial certificates
        Certificate[] certChain = new Certificate[] {converter.getCertificate(new CertBuilder().build())};
        CRL[] allCRLs = new CRL[10];

        for (int i = 0; i < 10; i++) {
            allCRLs[i] = createCRL(signerPrivKey, "CCCCCCCCCCCCC".getBytes());
        }

        // We will only variate the number of CRLs
        // so the other parameters are not important for this test
        MockedTSAClient tsc = new MockedTSAClient(1234);
        byte[] ocsp = "OOOOOOOO".getBytes();

        // Test 1: First test is the reference test
        crlList = new CRL[1];
        System.arraycopy(allCRLs, 0, crlList, 0, 1); // 1 CRL
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        LOG.debug("actualP7Size=" + actualP7Size + ", sumCertSizes=" + sumCRLSizes(crlList));
        referenceSize = actualP7Size;
        referenceCRLSize = sumCRLSizes(crlList);
        LOG.debug("referenceSize: " + actualP7Size);
        LOG.debug("referenceIssuerCertSize: " + referenceCRLSize);

        // Test 2: Increase the size of the certificate chain with 1 and test
        // that the final P7 does not increases with more than the size of the certificate
        crlList = new CRL[2];
        System.arraycopy(allCRLs, 0, crlList, 0, 2); // 2 CRLs
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        int diff = actualP7Size - referenceSize - sumCRLSizes(crlList, 1);
        LOG.debug("actualP7Size=" + actualP7Size + ", sumCertSizes=" + sumCRLSizes(crlList));
        assertEquals("no extra added for each certificate", 0, diff);

        // Test 3: Increase the size of the certificate chain with 2 and test
        // that the final P7 does not increases with more than the size of the certificates
        crlList = new CRL[3];
        System.arraycopy(allCRLs, 0, crlList, 0, 3); // 3 CRLs
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        diff = actualP7Size - referenceSize - sumCRLSizes(crlList, 1);
        LOG.debug("actualP7Size=" + actualP7Size + ", sumCertSizes=" + sumCRLSizes(crlList));
        assertEquals("no extra added for each certificate", 0, diff);

        // Test 4: Increase the size of the certificate chain with 49 and test
        // that the final P7 does not increases with more than the size of the certificates
        crlList = new CRL[10];
        System.arraycopy(allCRLs, 0, crlList, 0, 10); // 10 CRLs
        actualP7Size = getActualP7Size(signerPrivKey, somethingLargeEnough, certChain, crlList, ocsp, tsc);
        diff = actualP7Size - referenceSize - sumCRLSizes(crlList, 1);
        LOG.debug("actualP7Size=" + actualP7Size + ", sumCertSizes=" + sumCRLSizes(crlList));
        assertEquals("no extra added for each certificate", 0, diff);
    }

    /**
     * Test that the estimated value is within correct bounds when using different input values.
     *
     * Tests a few different combinations.
     *
     * TODO: Randomized stress testing would be good for this feature.
     *
     * The most important thing is that we don't estimate a too low value.
     *
     * Second thing is to not make a too large estimate. What quality of the
     * estimate we require is defined by the maxDiff constant. We can't calculate 
     * the size of the TS response (as it is performed after we construct the 
     * signature structure) so in this test only values under 7168 (the 
     * default estimate) are considered.
     *
     * @throws java.lang.Exception
     */
    public void test14calculateEstimatedSignatureSize() throws Exception {

        final int estimatedIntialTSResponseSize = 7168; // The value we assume for the TS response siz
        final int maxDiff = estimatedIntialTSResponseSize + 10000; // How far from the actual value we allow the algorithm to be

        KeyPair issuerKeyPair = CryptoUtils.generateRSA(1024);
        KeyPair signerKeyPair = CryptoUtils.generateRSA(1024);
        byte[] extensionBytes;

        Certificate signerCert = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(signerKeyPair.getPublic()).setSubject("CN=Signer").setIssuer("CN=Issuer1").build());
        Certificate issuerCert;
        Certificate[] certChain;
        CRL[] crlList;
        MockedTSAClient tsc;
        byte[] ocsp;

        // Subject, 0 extra bytes TS, 0 bytes OCSP, 0 CRLs (0 extra bytes)
        certChain = new Certificate[] {signerCert};
        tsc = new MockedTSAClient(0);
        ocsp = null;
        crlList = new CRL[0];
        assertEstimateCloseEnough(signerKeyPair.getPrivate(), certChain, tsc, ocsp, crlList, maxDiff);

        // Subject, Issuer(4123 extra bytes), 0 extra bytes TS, 0 bytes OCSP, 0 CRLs (0 extra bytes)
        extensionBytes = new byte[4123];
        issuerCert = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(issuerKeyPair.getPublic()).setSubject("CN=Issuer1").setIssuer("CN=Issuer1").addExtension(new CertExt(new ASN1ObjectIdentifier("1.2.3.4"), false, new DERBitString(extensionBytes))).build());
        certChain = new Certificate[] {signerCert, issuerCert};
        crlList = new CRL[0];
        tsc = new MockedTSAClient(0);
        ocsp = null;
        assertEstimateCloseEnough(signerKeyPair.getPrivate(), certChain, tsc, ocsp, crlList, maxDiff);

        // Subject, Issuer(17173 extra bytes), Issuer2 (123 extra bytes), 0 extra bytes TS, 0 bytes OCSP, 0 CRLs (0 extra bytes)
        extensionBytes = new byte[17173];
        issuerCert = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(issuerKeyPair.getPublic()).setSubject("CN=Issuer1").setIssuer("CN=Issuer1").addExtension(new CertExt(new ASN1ObjectIdentifier("1.2.3.4"), false, new DERBitString(extensionBytes))).build());
        X509Certificate issuerCert2 = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(issuerKeyPair.getPublic()).setSubject("CN=Issuer1").setIssuer("CN=Issuer1").addExtension(new CertExt(new ASN1ObjectIdentifier("1.2.3.4"), false, new DERBitString(new byte[123]))).build());
        certChain = new Certificate[] {signerCert, issuerCert, issuerCert2};
        crlList = new CRL[0];
        tsc = new MockedTSAClient(0);
        ocsp = null;
        assertEstimateCloseEnough(signerKeyPair.getPrivate(), certChain, tsc, ocsp, crlList, maxDiff);

        // Subject, Issuer(4123 extra bytes), 3178 extra bytes TS, 0 bytes OCSP, 0 CRLs (0 extra bytes)
        extensionBytes = new byte[4123];
        issuerCert = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(issuerKeyPair.getPublic()).setSubject("CN=Issuer1").setIssuer("CN=Issuer1").addExtension(new CertExt(new ASN1ObjectIdentifier("1.2.3.4"), false, new DERBitString(extensionBytes))).build());
        certChain = new Certificate[] {signerCert, issuerCert};
        crlList = new CRL[0];
        tsc = new MockedTSAClient(3178);
        ocsp = null;
        assertEstimateCloseEnough(signerKeyPair.getPrivate(), certChain, tsc, ocsp, crlList, maxDiff);

        // Subject, Issuer(17173 extra bytes), Issuer2 (123 extra bytes), 3178 extra bytes TS, 0 bytes OCSP, 0 CRLs (0 extra bytes)
        extensionBytes = new byte[17173];
        issuerCert = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(issuerKeyPair.getPublic()).setSubject("CN=Issuer1").setIssuer("CN=Issuer1").addExtension(new CertExt(new ASN1ObjectIdentifier("1.2.3.4"), false, new DERBitString(extensionBytes))).build());
        issuerCert2 = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(issuerKeyPair.getPublic()).setSubject("CN=Issuer1").setIssuer("CN=Issuer1").addExtension(new CertExt(new ASN1ObjectIdentifier("1.2.3.4"), false, new DERBitString(new byte[123]))).build());
        certChain = new Certificate[] {signerCert, issuerCert, issuerCert2};
        crlList = new CRL[0];
        tsc = new MockedTSAClient(3178);
        ocsp = null; //"OOOOOOOO".getBytes();
        assertEstimateCloseEnough(signerKeyPair.getPrivate(), certChain, tsc, ocsp, crlList, maxDiff);

        // Subject, Issuer(17173 extra bytes), Issuer2 (123 extra bytes), 3178 extra bytes TS, 1 bytes OCSP, 0 CRLs (0 extra bytes)
        //extensionBytes =
        //issuerCert =
        //issuerCert2 =
        //certChain =
        crlList = new CRL[0];
        tsc = new MockedTSAClient(3178);
        ocsp = new byte[1];
        assertEstimateCloseEnough(signerKeyPair.getPrivate(), certChain, tsc, ocsp, crlList, maxDiff);

        // Subject, Issuer(17173 extra bytes), Issuer2 (123 extra bytes), 3178 extra bytes TS, 1304 bytes OCSP, 0 CRLs (0 extra bytes)
        //extensionBytes =
        //issuerCert =
        //issuerCert2 = 
        //certChain = 
        //crlList = new CRL[0];
        tsc = new MockedTSAClient(3178);
        ocsp = new byte[1304];
        assertEstimateCloseEnough(signerKeyPair.getPrivate(), certChain, tsc, ocsp, crlList, maxDiff);

        // Subject, Issuer(17173 extra bytes), Issuer2 (123 extra bytes), 3178 extra bytes TS, 10102 bytes OCSP, 0 CRLs (0 extra bytes)
        //extensionBytes = 
        //issuerCert = 
        //issuerCert2 = 
        //certChain = 
        //crlList =
        tsc = new MockedTSAClient(3178);
        ocsp = new byte[10102];
        assertEstimateCloseEnough(signerKeyPair.getPrivate(), certChain, tsc, ocsp, crlList, maxDiff);

        // Subject, Issuer(0 extra bytes), 0 extra bytes TS, 0 bytes OCSP, 1 CRLs (0 extra bytes)
        extensionBytes = new byte[0];
        issuerCert = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(issuerKeyPair.getPublic()).setSubject("CN=Issuer1").setIssuer("CN=Issuer1").addExtension(new CertExt(new ASN1ObjectIdentifier("1.2.3.4"), false, new DERBitString(extensionBytes))).build());
        certChain = new Certificate[] {signerCert, issuerCert};
        crlList = new CRL[] {createCRL(signerKeyPair.getPrivate(), new byte[0])};
        tsc = new MockedTSAClient(0);
        ocsp = null;
        assertEstimateCloseEnough(signerKeyPair.getPrivate(), certChain, tsc, ocsp, crlList, maxDiff);

        // Subject, Issuer(17000 extra bytes), 0 extra bytes TS, 0 bytes OCSP, 1 CRLs (5432 extra bytes)
        extensionBytes = new byte[17000];
        issuerCert = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(issuerKeyPair.getPublic()).setSubject("CN=Issuer1").setIssuer("CN=Issuer1").addExtension(new CertExt(new ASN1ObjectIdentifier("1.2.3.4"), false, new DERBitString(extensionBytes))).build());
        certChain = new Certificate[] {signerCert, issuerCert};
        crlList = new CRL[] {createCRL(signerKeyPair.getPrivate(), new byte[5432])};
        tsc = new MockedTSAClient(0);
        ocsp = null;
        assertEstimateCloseEnough(signerKeyPair.getPrivate(), certChain, tsc, ocsp, crlList, maxDiff);

        // Subject, Issuer(17000 extra bytes), 0 extra bytes TS, 0 bytes OCSP, 2 CRLs (5432 extra bytes, 5076 extra bytes)
        extensionBytes = new byte[17000];
        issuerCert = converter.getCertificate(new CertBuilder().setIssuerPrivateKey(issuerKeyPair.getPrivate()).setSubjectPublicKey(issuerKeyPair.getPublic()).setSubject("CN=Issuer1").setIssuer("CN=Issuer1").addExtension(new CertExt(new ASN1ObjectIdentifier("1.2.3.4"), false, new DERBitString(extensionBytes))).build());
        certChain = new Certificate[] {signerCert, issuerCert};
        crlList = new CRL[] {createCRL(signerKeyPair.getPrivate(), new byte[5432]), createCRL(signerKeyPair.getPrivate(), new byte[5076])};
        tsc = new MockedTSAClient(0);
        ocsp = null;
        assertEstimateCloseEnough(signerKeyPair.getPrivate(), certChain, tsc, ocsp, crlList, maxDiff);
    }

    private void assertEstimateCloseEnough(PrivateKey signerPrivKey, Certificate[] certChain, MockedTSAClient tsc, byte[] ocsp, CRL[] crlList, int maxDiff) throws Exception {
        final int largeEnoughSpace = 32000;
        PDFSigner instance = new PDFSigner();

        int estimate = instance.calculateEstimatedSignatureSize(certChain, tsc, ocsp, crlList);

        int actual = getActualP7Size(signerPrivKey, largeEnoughSpace, certChain, crlList, ocsp, tsc);
        LOG.debug("estimate: " + estimate + ", actual: " + actual);

        // Estimate should not be to small
        assertTrue("estimate (" + estimate + ") must be at least " + actual, estimate >= actual);

        // Should not be larger than maxDiff
        int diff = estimate - actual;
        LOG.debug("diff: " + diff);
        assertTrue("diff (" + diff + ") <= maxDiff (" + maxDiff + ")", diff <= maxDiff);
    }

    /**
     * As we might not be in control of an external TSA the size they return might
     * be different from call to call that means that there is always a chance of
     * us doing a wrong size estimate. 
     * This tests tests that if we got it wrong the first time the second time
     * we make an estimate which is larger than the actual size returned from the 
     * first try.
     *
     * @throws java.lang.Exception
     */
    public void test14calculateEstimatedSignatureSize_resign() throws Exception {

        byte[] pdfbytes = readFile(sample);
        final KeyPair signerKeyPair = CryptoUtils.generateRSA(1024);
        final Certificate[] certChain = new Certificate[] {converter.getCertificate(new CertBuilder().build())};
        final Certificate signerCertificate = certChain[0];

        // any small value
        assertCanSign(pdfbytes, signerKeyPair, certChain, signerCertificate, 10);

        // medium value 3072
        assertCanSign(pdfbytes, signerKeyPair, certChain, signerCertificate, 3070);

        // the initial value just by the TSA client
        assertCanSign(pdfbytes, signerKeyPair, certChain, signerCertificate, 7168);
        assertCanSign(pdfbytes, signerKeyPair, certChain, signerCertificate, 7168 + 32);

        // slightly larger
        assertCanSign(pdfbytes, signerKeyPair, certChain, signerCertificate, 7168 + 32 + 1);

        // a larger value
        assertCanSign(pdfbytes, signerKeyPair, certChain, signerCertificate, 10123);

        // a large value
        assertCanSign(pdfbytes, signerKeyPair, certChain, signerCertificate, 15000 * 2 + 456);
    }

    /**
     * Test that setting both TSA_URL and TSA_WORKER results in a config error.
     * 
     * @throws Exception
     */
    public void test15TSA_URLandTSA_WORKERbothNotAllowed() throws Exception {
        WorkerConfig workerConfig = new WorkerConfig();

        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("TSA_URL", "http://localhost:8080/signserver/tsa?workerName=TimeStampSigner");
        workerConfig.setProperty("TSA_WORKER", "TimeStampSigner2");

        final PDFSigner instance = new PDFSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };
        instance.init(WORKER1, workerConfig, null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);

        assertTrue("Should contain error",
                fatalErrors.contains("Can not specify " + PDFSigner.TSA_URL + " and " + PDFSigner.TSA_WORKER + " at the same time."));
    }
    
    /**
     * Test that explicitly setting TSA_DIGESTALGORITHM to SHA-384 doesn't
     * give any error.
     * 
     * @throws Exception
     */
    public void test15TSA_DIGESTALGORITHM_sha384() throws Exception {
        WorkerConfig workerConfig = new WorkerConfig();

        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("TSA_WORKER", "TimeStampSigner2");
        workerConfig.setProperty("TSA_DIGESTALGORITHM", "SHA-384");

        final PDFSigner instance = new PDFSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };
        instance.init(WORKER1, workerConfig, null, null);

        final String fatalErrors = instance.getFatalErrors(null).toString();

        assertFalse("Should not contain error",
                    fatalErrors.contains("Illegal timestamping digest algorithm specified"));
    }
    
    /**
     * Test that explicitly setting TSA_DIGESTALGORITHM to SHA-384 doesn't
     * give any error.
     * 
     * @throws Exception
     */
    public void test15IllegalTSA_DIGESTALGORITHM() throws Exception {
        WorkerConfig workerConfig = new WorkerConfig();

        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("TSA_WORKER", "TimeStampSigner2");
        workerConfig.setProperty("TSA_DIGESTALGORITHM", "_non_existing_");

        final PDFSigner instance = new PDFSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };
        instance.init(WORKER1, workerConfig, null, null);

        final String fatalErrors = instance.getFatalErrors(null).toString();

        assertTrue("Should contain error: " + fatalErrors,
                   fatalErrors.contains("Illegal timestamping digest algorithm specified"));
    }
    
    /**
     * Test that providing illegal PDFSignerParameter values result in
     * configuration errors.
     *
     *
     * @throws Exception
     */
    public void test23Illegal_Value_Gives_Configuration_Errors() throws Exception {
        WorkerConfig workerConfig = new WorkerConfig();

        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("CERTIFICATION_LEVEL", "invalid_value");
        workerConfig.setProperty("SET_PERMISSIONS", "_invalid_value");
        workerConfig.setProperty("ADD_VISIBLE_SIGNATURE", "True");
        workerConfig.setProperty("VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH", "_invalid_value");
        workerConfig.setProperty("VISIBLE_SIGNATURE_RECTANGLE", "0,0,0");

        final PDFSigner instance = new PDFSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };
        instance.init(WORKER1, workerConfig, null, null);

        final String fatalErrors = instance.getFatalErrors(null).toString();

        assertTrue("Should contain error: " + fatalErrors,
                fatalErrors.contains("Unknown value for CERTIFICATION_LEVEL"));
        assertTrue("Should contain error: " + fatalErrors,
                fatalErrors.contains("Unknown permission value"));
        assertTrue("Should contain error: " + fatalErrors,
                fatalErrors.contains("Error reading custom image data from path specified"));
        assertTrue("Should contain error: " + fatalErrors,
                fatalErrors.contains("RECTANGLE property must contain 4 comma separated values with no spaces"));
    }

    /**
     * Test that providing empty strings for both TSA_URL and TSA_WORKER files are treated as not specified.
     *
     * @throws Exception
     */
    public void test20EmptyStringInTSA_URLAndTSA_WORKER_TreatedAsNotSpecified() throws Exception {

        final MockedCryptoToken token = generateToken(false, null);

        WorkerConfig workerConfig = new WorkerConfig();

        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("TSA_URL", "  ");
        workerConfig.setProperty("TSA_WORKER", "  ");
        workerConfig.setProperty("TYPE", "PROCESSABLE");

        final PDFSigner instance = new PDFSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return token;
            }
        };
        instance.init(WORKER1, workerConfig, null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);

        assertFalse("Should not contain error",
                fatalErrors.contains("Can not specify " + PDFSigner.TSA_URL + " and " + PDFSigner.TSA_WORKER + " at the same time."));
        assertTrue("There should not be any error so that we can assume that worker will be online", fatalErrors.isEmpty());
    }
    
    /**
     * Tests that Empty value for AUTHTYPE property should be allowed.
     *
     * @throws Exception
     */
    public void test20EmptyAuthTypeAllowed() throws Exception {

        final MockedCryptoToken token = generateToken(false, null);

        WorkerConfig workerConfig = new WorkerConfig();

        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("TSA_URL", "  ");
        workerConfig.setProperty("TSA_WORKER", "  ");
        workerConfig.setProperty("TYPE", "PROCESSABLE");
        workerConfig.setProperty("AUTHTYPE", "  ");

        final PDFSigner instance = new PDFSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return token;
            }
        };
        instance.init(WORKER1, workerConfig, null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);

        assertTrue("There should not be any error so that we can assume that worker will be online", fatalErrors.isEmpty());
    }

    /**
     * Tests that it is possible to sign a document with parameters specified as empty values.
     *
     * @throws java.lang.Exception
     */
    public void test20SigningWithEmptyParams() throws Exception {
        workerSession.setWorkerProperty(WORKER1, "DIGESTALGORITHM", "  ");
        workerSession.setWorkerProperty(WORKER1, "REASON", " ");
        workerSession.setWorkerProperty(WORKER1, "LOCATION", " ");
        workerSession.setWorkerProperty(WORKER1, "ADD_VISIBLE_SIGNATURE", " ");
        workerSession.setWorkerProperty(WORKER1, "VISIBLE_SIGNATURE_PAGE", " ");
        workerSession.setWorkerProperty(WORKER1, "VISIBLE_SIGNATURE_RECTANGLE", " ");
        workerSession.setWorkerProperty(WORKER1, "VISIBLE_SIGNATURE_CUSTOM_IMAGE_BASE64", "  ");
        workerSession.setWorkerProperty(WORKER1, "VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH", "  ");
        workerSession.setWorkerProperty(WORKER1, "VISIBLE_SIGNATURE_CUSTOM_IMAGE_SCALE_TO_RECTANGLE", "  ");
        workerSession.setWorkerProperty(WORKER1, "CERTIFICATION_LEVEL", "  ");
        workerSession.setWorkerProperty(WORKER1, "VISIBLE_SIGNATURE_CUSTOM_IMAGE_BASE64", "  ");
        workerSession.setWorkerProperty(WORKER1, "TSA_WORKER", "  ");
        workerSession.setWorkerProperty(WORKER1, "TSA_URL", "  ");
        workerSession.setWorkerProperty(WORKER1, "EMBED_CRL", "  ");
        workerSession.setWorkerProperty(WORKER1, "EMBED_OCSP_RESPONSE", "  ");

        workerSession.reloadConfiguration(WORKER1);

        signPDF(sampleOk);
    }
    
     /**
     * Tests that Signer refuses to sign if worker has configuration errors.
     *
     * @throws java.lang.Exception
     */
    public void test21NoSigningWhenWorkerMisconfigued() throws Exception {
        workerSession.setWorkerProperty(WORKER1, "DIGESTALGORITHM", "IllegalHash");
        workerSession.reloadConfiguration(WORKER1);

        try {
            signPDF(sampleOk);
            fail("Request should not have been accepted as worker must be offline now");
        } catch (SignServerException expected) {
            assertEquals("exception message", "Worker is misconfigured", expected.getMessage());
        }
    }
    
    /**
     * Tests that signing fails with an expected exception when the signing
     * certificate has a CDP and the fetched CRL is an empty file.
     */
    public void test22FailWithEmptyCRLFile() throws Exception {
        try {
            signPDF(sampleOk, WORKER2);
            fail("Request should not have been accepted");
        } catch (SignServerException expected) {
            assertEquals("exception message", "Empty CRL file fetched from CDP",
                         expected.getMessage());
        }
    }
    
    /**
     * Test that specifying an unknown hash algorithm gives a configuration
     * error.
     *
     * @throws Exception
     */
    public void test16IllegalDigestAlgorithm() throws Exception {
        WorkerConfig workerConfig = new WorkerConfig();

        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("DIGESTALGORITHM", "IllegalHash");

        final PDFSigner instance = new PDFSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };
        instance.init(WORKER1, workerConfig, null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);

        assertTrue("Should contain error",
                fatalErrors.contains("Illegal digest algorithm: IllegalHash"));
    }

    /**
     * Test that setting a hash algorithm other than SHA1
     * gives an error when using DSA keys.
     *
     * @throws Exception
     */
    public void test17OnlySHA1AcceptedForDSA() throws Exception {
        final MockedCryptoToken token = generateToken(true, null);
        final MockedPDFSigner instance = new MockedPDFSigner(token);

        final WorkerConfig workerConfig = new WorkerConfig();

        workerConfig.setProperty("NAME", "TestSignerDSA");
        workerConfig.setProperty("DIGESTALGORITHM", "SHA256");

        instance.init(WORKER2, workerConfig, null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);

        assertTrue("Should contain error", fatalErrors.contains(ILLEGAL_DIGEST_FOR_DSA_MESSAGE));
    }

    /**
     * Test that explicitly setting SHA1 for DSA keys works.
     *
     * @throws Exception
     */
    public void test18SHA1acceptedForDSA() throws Exception {
        final MockedCryptoToken token = generateToken(true, null);
        final MockedPDFSigner instance = new MockedPDFSigner(token);

        final WorkerConfig workerConfig = new WorkerConfig();

        workerConfig.setProperty("NAME", "TestSignerDSA");
        workerConfig.setProperty("DIGESTALGORITHM", "SHA1");

        instance.init(WORKER2, workerConfig, null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);

        assertFalse("Should not contain error", fatalErrors.contains(ILLEGAL_DIGEST_FOR_DSA_MESSAGE));
    }

    /**
     * Test that setting the hash algorithm to SHA256
     * is accepted for RSA keys.
     *
     * @throws Exception
     */
    public void test19SHA256AcceptedForRSA() throws Exception {
        final MockedCryptoToken token = generateToken(false, null);
        final MockedPDFSigner instance = new MockedPDFSigner(token);

        final WorkerConfig workerConfig = new WorkerConfig();

        workerConfig.setProperty("NAME", "TestSignerDSA");
        workerConfig.setProperty("DIGESTALGORITHM", "SHA256");

        instance.init(WORKER2, workerConfig, null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);

        assertFalse("Should not contain error", fatalErrors.contains(ILLEGAL_DIGEST_FOR_DSA_MESSAGE));
    }

    /**
     * Helper method creating a mocked token, using DSA or RSA keys.
     *
     * @param useDSA True if DSA is to be used, otherwise RSA
     * @param cdpUrl URL to use if a CDP URL should be included in the signing
     *               cert, if null, no CDP URL is added.
     * @return Mocked crypto token
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws CertBuilderException
     * @throws CertificateException
     */
    private MockedCryptoToken generateToken(final boolean useDSA, final String cdpUrl) throws NoSuchAlgorithmException, NoSuchProviderException,
            CertBuilderException, CertificateException {
        final KeyPair signerKeyPair = useDSA ? CryptoUtils.generateDSA(1024) : CryptoUtils.generateRSA(1024);
        CertBuilder certBuilder = new CertBuilder();
        
        if (cdpUrl != null) {
            certBuilder = certBuilder.addCDPURI(cdpUrl);
        }

        final Certificate[] certChain = new Certificate[] {converter.getCertificate(certBuilder.build())};
        final Certificate signerCertificate = certChain[0];
        final String provider = "BC";

        final MockedCryptoToken token = new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), provider);
        return token;
    }

    /**
     * Mocked PDF signer using a mocked crypto token.
     */
    private class MockedPDFSigner extends PDFSigner {
        private final MockedCryptoToken mockedToken;

        public MockedPDFSigner(final MockedCryptoToken mockedToken) {
            this.mockedToken = mockedToken;
        }

        @Override
        public ICryptoTokenV4 getCryptoToken(final IServices services) {
            return mockedToken;
        }
    }

    
    /**
     * Tests that we don't get an exception trying to sign a document with the
     * given parameters.
     * The idea is that if the estimate is too small an retry is done so this 
     * should always succeed.
     */
    private void assertCanSign(final byte[] pdfbytes, final KeyPair signerKeyPair, final Certificate[] certChain, final Certificate signerCertificate, final int tsSize) throws Exception {

        final MockedTSAClient tsc = new MockedTSAClient(tsSize);
        final String provider = "BC";

        final MockedCryptoToken token = new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), provider);

        PDFSigner instance = new PDFSigner() {

            @Override
            protected TSAClient getTimeStampClient(String url, String username, String password, ASN1ObjectIdentifier digestAlgo) {
                return tsc;
            }

            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) {
                return token;
            }

        };

        final WorkerConfig config = new WorkerConfig();
        final List<String> configErrors = new LinkedList<>();
        config.setProperty("TSA_URL", "http://any-tsa.example.com");
        final PDFSignerParameters params = new PDFSignerParameters(1234, config, configErrors);

        instance.setIncludeCertificateLevels(1);

        try (CloseableWritableData responseData = createResponseData(false)) {
            final DefaultDigestAlgorithmIdentifierFinder algFinder =
                new DefaultDigestAlgorithmIdentifierFinder();
                final AlgorithmIdentifier ai = algFinder.find("SHA-256");
                final ASN1ObjectIdentifier tsaDigestAlgorithm = ai.getAlgorithm();
            
            instance.addSignatureToPDFDocument(token.acquireCryptoInstance("any-alias", Collections.<String, Object>emptyMap(), null), params, pdfbytes, null, null, 0,
                    null, responseData, null, tsaDigestAlgorithm, "SHA-256");
            byte[] signedPdfbytes = responseData.toReadableData().getAsByteArray();
            assertNotNull(signedPdfbytes);
            assertTrue("some data", signedPdfbytes.length > 0);
        } catch (SignServerException ex) {
            LOG.debug("failed to sign", ex);
            fail(ex.getMessage());
        }

        if (!tsc.isCalled()) {
            throw new Exception("Test must be configured to use TSA otherwise we are not testing anything...");
        }
        LOG.debug("Private key used: " + token.getPrivateKeyCalls() + "\n");
    }

    /**
     * Create a signature with the given input.
     * @return The size of the produced PKCS#7 structure.
     */
    private int getActualP7Size(PrivateKey signerPrivKey, int estimate, Certificate[] certChain, CRL[] crlList, byte[] ocsp, MockedTSAClient tsc) throws Exception {
        PDFSigner instance = new PDFSigner();
        PdfReader reader = new PdfReader(readFile(sample), null);
        ByteArrayOutputStream fout = new ByteArrayOutputStream();
        PdfStamper stp = PdfStamper.createSignature(reader, fout, '\0', null, true);
        PdfSignatureAppearance sap = stp.getSignatureAppearance();
        sap.setCrypto(null, certChain, crlList, PdfSignatureAppearance.SELF_SIGNED);
        PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("adbe.pkcs7.detached"));
        dic.setReason("Reasons...");
        dic.setLocation("Location...");
        dic.setDate(new PdfDate(Calendar.getInstance()));
        sap.setCryptoDictionary(dic);
        byte[] encodedSig = instance.calculateSignature(new PdfPKCS7(signerPrivKey, certChain, crlList, "SHA1", null, false), estimate, MessageDigest.getInstance("SHA1"), Calendar.getInstance(), null, certChain, tsc, ocsp, sap, "SHA-256");

        return encodedSig.length;
    }

    private byte[] signPDF(File file) throws Exception {
        return signProtectedPDF(file, WORKER1, null);
    }
    
    private byte[] signPDF(final File file, final int workerId) throws Exception {
        return signProtectedPDF(file, workerId, null);
    }

    private byte[] signProtectedPDF(final File file, final String password) throws Exception {
        return signProtectedPDF(file, WORKER1, password);
    }
    
    private byte[] signProtectedPDF(final File file, final int workerId,
            final String password) throws Exception {
        LOG.debug("Tests signing of " + file.getName() + " with password:");
        if (password == null) {
            LOG.debug("null");
        } else {
            LOG.debug("\"" + password + "\" " + Arrays.toString(password.toCharArray()));
        }

        RequestContext context = new RequestContext();
        RequestMetadata.getInstance(context).put(RequestContext.METADATA_PDFPASSWORD, password);

        try (
                CloseableReadableData requestData = createRequestDataKeepingFile(file);
                CloseableWritableData responseData = createResponseData(true);
            ) {
            final Response response = 
                    processSession.process(createAdminInfo(), new WorkerIdentifier(workerId), 
                            new SignatureRequest(200, requestData, responseData),
                            context);
            assertNotNull(response);
            return responseData.toReadableData().getAsByteArray();
        }
    }

    private void setupWorkers()
            throws NoSuchAlgorithmException, NoSuchProviderException,
            CertBuilderException, CertificateException, FileNotFoundException,
            IOException {

        final GlobalConfigurationSessionMock globalMock
                = new GlobalConfigurationSessionMock();
        final WorkerSessionMock workerMock = new WorkerSessionMock();
        globalConfig = globalMock;
        workerSession = workerMock;
        processSession = workerMock;

        // WORKER1
        final MockedCryptoToken token = generateToken(false, null);
        {
            final int workerId = WORKER1;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestPDFSigner1");
            config.setProperty("KEYSTOREPATH",
                    getSignServerHome() + File.separator + "res" + File.separator +
                            "test" + File.separator + "dss10" + File.separator +
                            "dss10_signer1.p12");
            config.setProperty("KEYSTORETYPE", "PKCS12");
            config.setProperty("KEYSTOREPASSWORD", "foo123");
            config.setProperty("DEFAULTKEY", "Signer 1");
            config.setProperty("DIGESTALGORITHM", "SHA256");

            config.setProperty(AUTHTYPE, "NOAUTH");

            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new PDFSigner() {
                @Override
                public ICryptoTokenV4 getCryptoToken(final IServices services) {
                    return token;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }
        
        // WORKER2
        // signer with a signer certificate with a CDP URL pointing at an empty file
        final File empty = File.createTempFile("test", "crl");
        // WORKER1
        final MockedCryptoToken tokenCRL = generateToken(false, empty.toURI().toString());
        {
            final int workerId = WORKER2;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestPDFSigner2");
            config.setProperty("KEYSTOREPATH",
                    getSignServerHome() + File.separator + "res" + File.separator +
                            "test" + File.separator + "dss10" + File.separator +
                            "dss10_signer1.p12");
            config.setProperty("KEYSTORETYPE", "PKCS12");
            config.setProperty("KEYSTOREPASSWORD", "foo123");
            config.setProperty("DEFAULTKEY", "Signer 1");
            config.setProperty("DIGESTALGORITHM", "SHA256");
            config.setProperty("EMBED_CRL", "true");

            config.setProperty(AUTHTYPE, "NOAUTH");

            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new PDFSigner() {
                @Override
                public ICryptoTokenV4 getCryptoToken(final IServices services) {
                    return tokenCRL;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }
    }

    private byte[] readFile(File file) throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(
                file))) {
            int b;
            while ((b = in.read()) != -1) {
                bout.write(b);
            }
        }
        return bout.toByteArray();
    }

    private Permissions getPermissions(byte[] pdfBytes, byte[] password) throws IOException {
        PdfReader reader = new PdfReader(pdfBytes, password);
        return Permissions.fromInt(reader.getPermissions());
    }

    private int getCryptoMode(byte[] pdfBytes, byte[] password) throws IOException {
        PdfReader reader = new PdfReader(pdfBytes, password);
        return reader.getCryptoMode();
    }

    /**
     * Asserts that the password really can be used as user password.
     */
    private static void assertUserPassword(byte[] pdfBytes, String password) throws IOException, DocumentException {
        // This will fail unless password is owner or user
        System.out.println("password: " + password);
        PdfReader reader = new PdfReader(pdfBytes, password.getBytes("ISO-8859-1"));
        reader.close();

        // Still if the document did not contain a password it would not have failed yet
        // Test that it really fails when specifying a wrong password
        boolean exceptionThrown = true;
        try {
            PdfReader reader2 = new PdfReader(pdfBytes, "_ABSOLUTLEY_NOT_THE_RIGHT_PASSWORD_".getBytes("ISO-8859-1"));
            reader2.close();
            exceptionThrown = false;
        } catch (IOException ok) {
            LOG.debug(ok.getMessage());
        }
        if (!exceptionThrown) {
            throw new IOException("PDF did not require a password");
        }
    }

    /**
     * Asserts that the supplied password is user but not an owner password.
     */
    private static void assertUserNotOwnerPassword(byte[] pdfBytes, String password) throws IOException, DocumentException {
        // This will fail unless password is owner or user
        PdfReader reader;
        PdfStamper stp;
        try {
            reader = new PdfReader(pdfBytes, password == null ? null : password.getBytes("ISO-8859-1"));
        } catch (BadPasswordException ex) {
            fail("Not a valid password: " + ex.getMessage());
            return;
        }

        try {
            // This should fail if password is not owner
            ByteArrayOutputStream fout = new ByteArrayOutputStream();
            stp = PdfStamper.createSignature(reader, fout, '\0', null, false);
            stp.setEncryption(reader.computeUserPassword(), password == null ? null : password.getBytes("ISO-8859-1"), 0, 1);
            fail("Password was an owner password");
        } catch (BadPasswordException ok) {
            LOG.debug("ok: " + ok.getMessage());
        }
    }

    /**
     * Asserts that the password really can be used as owner password.
     */
    private static void assertOwnerPassword(byte[] pdfBytes, String password) throws IOException, DocumentException {
        // This will fail unless password is owner or user
        PdfReader reader = new PdfReader(pdfBytes, password.getBytes("ISO-8859-1"));
        ByteArrayOutputStream fout = new ByteArrayOutputStream();
        PdfStamper stp = PdfStamper.createSignature(reader, fout, '\0', null, false);

        // This will fail unless password is owner
        stp.setEncryption(reader.computeUserPassword(), password.getBytes("ISO-8859-1"), 0, 1);

        // Still if the document did not contain a password it would not have failed yet
        // Test that it really fails when specifying a wrong password
        boolean exceptionThrown = true;
        try {
            PdfReader reader2 = new PdfReader(pdfBytes, "_ABSOLUTLEY_NOT_THE_RIGHT_PASSWORD_".getBytes("ISO-8859-1"));
            reader2.close();
            exceptionThrown = false;
        } catch (IOException ok) {
            LOG.debug(ok.getMessage());
        }
        if (!exceptionThrown) {
            throw new IOException("PDF did not require a password");
        }
    }
}
