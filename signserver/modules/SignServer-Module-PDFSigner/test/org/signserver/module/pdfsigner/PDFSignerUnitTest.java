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
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfStamper;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.Certificate;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;
import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.WorkerSessionMock;

/**
 * Unit tests for PDFSigner.
 *
 * This tests uses a mockup and does not require an running application
 * server. Tests that require that can be placed among the system tests.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class PDFSignerUnitTest extends TestCase {

    /** Logger for this class. */
    public static final Logger LOG = Logger.getLogger(PDFSignerUnitTest.class);
    
    /** Worker7897: Default algorithms, default hashing setting. */
    private static final int WORKER1 = 7897;

    private static final String NAME = "NAME";
    private static final String AUTHTYPE = "AUTHTYPE";
    
    private static final String CRYPTOTOKEN_CLASSNAME = 
            "org.signserver.server.cryptotokens.HardCodedCryptoToken";
    private final String SAMPLE_OWNER123_PASSWORD = "owner123";
    private final String SAMPLE_USER_AAA_PASSWORD = "user\u00e5\u00e4\u00f6";
    
    private IGlobalConfigurationSession.IRemote globalConfig;
    private IWorkerSession.IRemote workerSession;

    private File sampleOk;
    private File sampleRestricted;

    private File sample;
    private File sampleOpen123;
    private File sampleOpen123Owner123;
    private File sampleOwner123;
    private File sampleUseraao;
    private File sampleCertifiedSigningAllowed;
    private File sampleCertifiedNoChangesAllowed;
    private File sampleCertifiedFormFillingAllowed;
    private File sampleSigned;
//    private File sampleLowprintingOwner123;
    
    public PDFSignerUnitTest() {
        SignServerUtil.installBCProvider();
        File home = new File(System.getenv("SIGNSERVER_HOME"));
        assertTrue("Environment variable SIGNSERVER_HOME", home.exists());
        sampleOk = new File(home, "res/test/ok.pdf");
        sampleRestricted = new File(home, "res/test/sample-restricted.pdf");
        sample = new File(home, "res/test/pdf/sample.pdf");
        sampleOpen123 = new File(home, "res/test/pdf/sample-open123.pdf");
        sampleOpen123Owner123 = new File(home, "res/test/pdf/sample-open123-owner123.pdf");
        sampleOwner123 = new File(home, "res/test/pdf/sample-owner123.pdf");
        sampleUseraao = new File(home, "res/test/pdf/sample-useraao.pdf");
        sampleCertifiedSigningAllowed = new File(home, "res/test/pdf/sample-certified-signingallowed.pdf");
        sampleCertifiedNoChangesAllowed = new File(home, "res/test/pdf/sample-certified-nochangesallowed.pdf");
        sampleCertifiedFormFillingAllowed = new File(home, "res/test/pdf/sample-certified-formfillingallowed.pdf");
        sampleSigned = new File(home, "res/test/pdf/sample-signed.pdf");
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
        byte[] data = readFile(sampleOk);

        final GenericSignRequest request = new GenericSignRequest(100,
                data);

        final GenericSignResponse response = (GenericSignResponse)
                workerSession.process(WORKER1, request, new RequestContext());
        assertEquals("requestId", 100, response.getRequestID());

        Certificate signercert = response.getSignerCertificate();
        assertNotNull(signercert);
    }

    /**
     * Tries to sign a PDF with document restrictions. As no password is 
     * supplied it throws an IllegalRequestException.
     * @throws Exception in case of error
     */
    public void test02SignWithRestrictionsNoPasswordSupplied() throws Exception { 
        try {
            workerSession.process(
                WORKER1,
                new GenericSignRequest(200, readFile(sampleRestricted)),
                new RequestContext());
            fail("Should have thrown exception");
        } catch (IllegalRequestException ignored) {
            // OK
        }

        try {
            workerSession.process(
                WORKER1,
                new GenericSignRequest(200, readFile(sampleOpen123)),
                new RequestContext());
            fail("Should have thrown exception");
        } catch (IllegalRequestException ignored) {
            // OK
    }

        try {
            workerSession.process(
                WORKER1,
                new GenericSignRequest(200, readFile(sampleOpen123Owner123)),
                new RequestContext());
            fail("Should have thrown exception");
        } catch (IllegalRequestException ignored) {
            // OK
        }
        
        try {
            workerSession.process(
                WORKER1,
                new GenericSignRequest(200, readFile(sampleOwner123)),
                new RequestContext());
            fail("Should have thrown exception");
        } catch (IllegalRequestException ignored) {
            // OK
        }
    }
    
    /**
     * Tries to sign a PDF with document restrictions. As the correct passwords 
     * are supplied it should succeed.
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
     */
    public void test04SetPermissions() throws Exception {
        
        doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, Arrays.asList("ALLOW_PRINTING", "ALLOW_MODIFY_CONTENTS", "ALLOW_COPY", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_FILL_IN", "ALLOW_SCREENREADERS", "ALLOW_ASSEMBLY", "ALLOW_DEGRADED_PRINTING"));
        doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, Arrays.asList("ALLOW_PRINTING", "ALLOW_MODIFY_CONTENTS", "ALLOW_COPY", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_FILL_IN", "ALLOW_ASSEMBLY", "ALLOW_DEGRADED_PRINTING"));
        doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, Arrays.asList( "ALLOW_MODIFY_CONTENTS", "ALLOW_COPY", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_FILL_IN", "ALLOW_ASSEMBLY", "ALLOW_DEGRADED_PRINTING"));
        doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, Arrays.asList( "ALLOW_COPY", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_FILL_IN", "ALLOW_ASSEMBLY", "ALLOW_DEGRADED_PRINTING"));
        doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, Arrays.asList( "ALLOW_COPY", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_FILL_IN", "ALLOW_DEGRADED_PRINTING"));
        doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, Arrays.asList( "ALLOW_COPY", "ALLOW_FILL_IN", "ALLOW_DEGRADED_PRINTING"));
        doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, Arrays.asList( "ALLOW_FILL_IN", "ALLOW_DEGRADED_PRINTING"));
        doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, Arrays.asList( "ALLOW_FILL_IN"));
        doTestSetPermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, new LinkedList<String>());
        
        // Without SET_PERMISSIONS the original permissions should remain
        // The sampleOwner123 originally has: ALLOW_FILL_IN,ALLOW_MODIFY_ANNOTATIONS,ALLOW_MODIFY_CONTENTS
        workerSession.removeWorkerProperty(WORKER1, "SET_PERMISSIONS");
        workerSession.reloadConfiguration(WORKER1);
        Set<String> expected = new HashSet<String>(Arrays.asList("ALLOW_FILL_IN", "ALLOW_MODIFY_ANNOTATIONS", "ALLOW_MODIFY_CONTENTS"));
        Permissions actual = getPermissions(signProtectedPDF(sampleOwner123, SAMPLE_OWNER123_PASSWORD), 
                SAMPLE_OWNER123_PASSWORD.getBytes("ISO-8859-1"));
        assertEquals(expected, actual.asSet());
    }
    
    private void doTestSetPermissions(int workerId, File pdf, String password, Collection<String> permissions) throws Exception {
        Set<String> expected = new HashSet<String>(permissions);
        workerSession.setWorkerProperty(workerId, "SET_PERMISSIONS", toString(expected, ","));
        workerSession.reloadConfiguration(workerId);
        Permissions actual = getPermissions(signProtectedPDF(pdf, password), 
                password == null ? null : password.getBytes("ISO-8859-1"));
        assertEquals(expected, actual.asSet());
    }
    
    private void doTestRemovePermissions(int workerId, File pdf, String password, Collection<String> removePermissions, Collection<String> expected) throws Exception {
        Set<String> expectedSet = new HashSet<String>(expected);
        workerSession.setWorkerProperty(workerId, "REMOVE_PERMISSIONS", toString(removePermissions, ","));
        workerSession.reloadConfiguration(workerId);
        Permissions actual = getPermissions(signProtectedPDF(pdf, password), 
                password.getBytes("ISO-8859-1"));
        assertEquals(expectedSet, actual.asSet());
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
     */
    public void test04RemovePermissions() throws Exception {
        // The sampleOwner123 originally has: ALLOW_FILL_IN,ALLOW_MODIFY_ANNOTATIONS,ALLOW_MODIFY_CONTENTS
        doTestRemovePermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, Arrays.asList("ALLOW_FILL_IN"), Arrays.asList("ALLOW_MODIFY_ANNOTATIONS", "ALLOW_MODIFY_CONTENTS"));
        doTestRemovePermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, Arrays.asList("ALLOW_MODIFY_ANNOTATIONS"), Arrays.asList("ALLOW_FILL_IN", "ALLOW_MODIFY_CONTENTS"));
        doTestRemovePermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, Arrays.asList("ALLOW_MODIFY_CONTENTS"), Arrays.asList("ALLOW_FILL_IN", "ALLOW_MODIFY_ANNOTATIONS"));
        
        doTestRemovePermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, Arrays.asList("ALLOW_MODIFY_ANNOTATIONS", "ALLOW_MODIFY_CONTENTS"), Arrays.asList("ALLOW_FILL_IN"));
        doTestRemovePermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, Arrays.asList("ALLOW_FILL_IN", "ALLOW_MODIFY_CONTENTS"), Arrays.asList("ALLOW_MODIFY_ANNOTATIONS"));
        doTestRemovePermissions(WORKER1, sampleOwner123, SAMPLE_OWNER123_PASSWORD, Arrays.asList("ALLOW_FILL_IN", "ALLOW_MODIFY_ANNOTATIONS"), Arrays.asList("ALLOW_MODIFY_CONTENTS"));
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
     */
    public void test07ChangePermissionOfUnprotectedDocument() throws Exception {
        doTestSetPermissions(WORKER1, sampleOk, null, Arrays.asList( "ALLOW_FILL_IN", "ALLOW_DEGRADED_PRINTING"));
    }
    
    /**
     * Test helper method for asserting that a certain owner password is really 
     * set.
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
     */
    public void test10SignCertifiedDocument() throws Exception {
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
    }
    
    /**
     * Tests that it is possible to certify a document that already is signed.
     */
    public void test11CertifySignedDocument() throws Exception {
        workerSession.setWorkerProperty(WORKER1, "CERTIFICATION_LEVEL", "FORM_FILLING");
        workerSession.reloadConfiguration(WORKER1);
        signPDF(sampleSigned);
        
        workerSession.setWorkerProperty(WORKER1, "CERTIFICATION_LEVEL", "FORM_FILLING_AND_ANNOTATIONS");
        workerSession.reloadConfiguration(WORKER1);
        signPDF(sampleSigned);
        
        workerSession.setWorkerProperty(WORKER1, "CERTIFICATION_LEVEL", "NO_CHANGES_ALLOWED");
        workerSession.reloadConfiguration(WORKER1);
        signPDF(sampleSigned);
    }
    
    /**
     * Tests that it is possible to sign an already signed document.
     */
    public void test12SignSignedDocument() throws Exception {
        signPDF(sampleSigned);
    }
    
    /**
     * Tests that it is not possible to certify an already certified document.
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
    
    private byte[] signPDF(File file) throws Exception {
        return signProtectedPDF(file, null);
    }
    
    private byte[] signProtectedPDF(File file, String password) throws Exception {
        LOG.debug("Tests signing of " + file.getName() + " with password:");
        if (password == null) {
            LOG.debug("null");
        } else {
            LOG.debug("\"" + password + "\" " + Arrays.toString(password.toCharArray()));
        }
        
        RequestContext context = new RequestContext();
        Map<String, String> metadata = new HashMap<String, String>();
        metadata.put(RequestContext.METADATA_PDFPASSWORD, password);
        context.put(RequestContext.REQUEST_METADATA, metadata);
        
        final GenericSignResponse response = 
                (GenericSignResponse) workerSession.process(WORKER1, 
                new GenericSignRequest(200, readFile(file)), 
                context);
        assertNotNull(response);
        return response.getProcessedData();
    }

    private void setupWorkers() {

        final GlobalConfigurationSessionMock globalMock
                = new GlobalConfigurationSessionMock();
        final WorkerSessionMock workerMock = new WorkerSessionMock(globalMock);
        globalConfig = globalMock;
        workerSession = workerMock;

        // WORKER1
        {
            final int workerId = WORKER1;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestPDFSigner1");
            config.setProperty(AUTHTYPE, "NOAUTH");
            
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new PDFSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }
        
    }

    private byte[] readFile(File file) throws IOException {
        BufferedInputStream in = new BufferedInputStream(new FileInputStream(
                file));
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            bout.write(b);
        }
        return bout.toByteArray();
    }

    private Permissions getPermissions(byte[] pdfBytes, byte[] password) throws IOException {
        PdfReader reader = new PdfReader(pdfBytes, password);
        return Permissions.fromInt(reader.getPermissions());
    }

    /**
     * Asserts that the password really can be used as user password.
     */
    private static void assertUserPassword(byte[] pdfBytes, String password) throws IOException, DocumentException {
        // This will fail unless password is owner or user
        System.out.println("password: " + password);
        PdfReader reader = new PdfReader(pdfBytes, password.getBytes("ISO-8859-1"));
        
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
