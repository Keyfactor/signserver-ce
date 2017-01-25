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
package org.signserver.server.enterprise.data.impl;

import com.lowagie.text.Chunk;
import com.lowagie.text.Document;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.Security;
import java.security.Signature;
import java.security.Timestamp;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Properties;
import java.util.Random;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.NullOutputStream;
import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.junit.AfterClass;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.cli.spi.CommandContext;
import org.signserver.cli.spi.CommandFactoryContext;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.client.cli.defaultimpl.SignDocumentCommand;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.util.PathUtil;
import org.signserver.server.data.impl.UploadConfig;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests for the GenericProcessServlet with larg files and for different
 * signers.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class LargeFileGenericProcessServletTest {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(LargeFileGenericProcessServletTest.class);
    
    private static final int PLAINSIGNER_ID = 2003;
    private static final String PLAINSIGNER_NAME = "PlainSigner2003";
    private static final int JARCHIVESIGNER_ID = 2004;
    private static final String JARCHIVESIGNER_NAME = "JArchiveSigner2004";
    
    private static File repository;
    private static File large300;

    private final ModulesTestCase test = new ModulesTestCase();


    /**
     * Generate some large files to test with.
     * @throws Exception 
     */
    @BeforeClass
    public static void setUpClass() throws Exception {
        LOG.info("setUpClass");
        repository = new File(PathUtil.getAppHome(), "tmp");
        
        // Create a 300 MB XML document
        large300 = new File(repository, "largefile-300.tmp");
        large300.deleteOnExit();
        try (FileOutputStream fos = new FileOutputStream(large300)) {
            Random random = new Random(5678901);
            byte[] bytes = new byte[1024];
            Arrays.fill(bytes, (byte) 'A');
            for (int i = 0; i < 300 * FileUtils.ONE_MB / bytes.length; i++) {
                random.nextBytes(bytes);
                fos.write(bytes);
            }
        }
        LOG.info("File size: " + large300.length());
        
        Security.addProvider(new BouncyCastleProvider());
    }
    
    /**
     * Remove the test files.
     */
    @AfterClass
    public static void tearDownClass() {
        FileUtils.deleteQuietly(large300);
    }

    /**
     * Sets up a dummy signer.
     * @throws Exception in case of error
     */
    @Test
    public void test00SetupDatabase() throws Exception {
        test.addCMSSigner1();
        test.addPDFSigner1();
        test.addSigner("org.signserver.module.cmssigner.PlainSigner", PLAINSIGNER_ID, PLAINSIGNER_NAME, true);
        test.addJArchiveSigner(JARCHIVESIGNER_ID, JARCHIVESIGNER_NAME, true);

        // Allow large files
        test.getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, UploadConfig.HTTP_MAX_UPLOAD_SIZE, String.valueOf(500 * FileUtils.ONE_MB));
    }

    /**
     * Test signing of a large file using PlainSigner.
     * @throws Exception 
     */
    @Test
    public void test10LargePlain() throws Exception {
        LOG.info("test10LargePlain");

        File outFile = null;
        try {
            outFile = File.createTempFile("large-plain", "-signed.tmp", repository);

            execute("signdocument", 
                            "-workername", PLAINSIGNER_NAME, 
                            "-infile", large300.getAbsolutePath(),
                            "-outfile", outFile.getAbsolutePath());
        
            Certificate certificate = test.getWorkerSession().getSignerCertificate(new WorkerIdentifier(PLAINSIGNER_ID));
            
            // Verify signature
            Signature signature = Signature.getInstance("SHA1withRSA"); // Note: default signature algorithm in PlainSigner
            signature.initVerify(certificate);
            try (FileInputStream fin = new FileInputStream(large300)) {
                final byte[] buffer = new byte[4096]; 
                int n = 0;
                while (-1 != (n = fin.read(buffer))) {
                    signature.update(buffer, 0, n);
                }
            }
            assertTrue("verify signature", signature.verify(FileUtils.readFileToByteArray(outFile)));
        } finally {
            FileUtils.deleteQuietly(outFile);
        }
    }

    /**
     * Test signing of a large file using the CMSSigner and a detached
     * signature.
     * @throws Exception 
     */
    @Test
    public void test20LargeCMSDetached() throws Exception {
        LOG.info("test20LargeCMSDetached");

        // Set detached signature
        test.getWorkerSession().setWorkerProperty(test.getSignerIdCMSSigner1(), "DETACHEDSIGNATURE", "TRUE");
        test.getWorkerSession().reloadConfiguration(test.getSignerIdCMSSigner1());

        // Allow large files
        test.getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, UploadConfig.HTTP_MAX_UPLOAD_SIZE, String.valueOf(500 * FileUtils.ONE_MB));
        
        File outFile = null;
        try {
            outFile = File.createTempFile("large-cms", "-signed.tmp", repository);

            execute("signdocument", 
                        "-workername", test.getSignerNameCMSSigner1(), 
                        "-infile", large300.getAbsolutePath(),
                        "-outfile", outFile.getAbsolutePath());
            
        final CMSSignedData signedData = new CMSSignedData(FileUtils.readFileToByteArray(outFile));
        assertNotNull("signed data", signedData);

        } finally {
            FileUtils.deleteQuietly(outFile);
        }
    }
    
    /**
     * Test signing of a large PDF using PDFSigner.
     * @throws Exception 
     */
    @Test
    public void test30LargePDF() throws Exception {
        LOG.info("test10LargePDF");

        File largePDF300 = null;
        PdfReader reader = null;
        try {
            // Create a x MB PDF document
            largePDF300 = new File(repository, "largefile-300.pdf");
            largePDF300.deleteOnExit();
            try (FileOutputStream fos = new FileOutputStream(largePDF300)) {
                Document document = new Document(PageSize.A4, 50, 50, 50, 50);
                PdfWriter writer = PdfWriter.getInstance(document, fos);
                document.open();
                document.newPage();
                document.add(new Chunk(""));
                document.add(new Paragraph("Test document with large attachment"));

                writer.addFileAttachment("A large file", null, large300.getAbsolutePath(), "large.xml");

                document.close();            
            }
            LOG.info("File size: " + largePDF300.length());

            File outFile = null;
            try {
                outFile = File.createTempFile("large-pdf", "-signed.tmp", repository);

                execute("signdocument", 
                                "-workername", test.getSignerNamePDFSigner1(), 
                                "-infile", largePDF300.getAbsolutePath(),
                                "-outfile", outFile.getAbsolutePath());

                if (outFile.length() < largePDF300.length()) {
                    throw new Exception("outFile only " + outFile.length() + " bytes. Out of disk space?");
                }
                
                // Verify signature (with the included certificate)
                reader = new PdfReader(outFile.getAbsolutePath());
                AcroFields acroFields = reader.getAcroFields();
                String sigName = (String) acroFields.getSignatureNames().iterator().next();
                assertTrue("covers whole file", acroFields.signatureCoversWholeDocument(sigName));
                PdfPKCS7 p7 = acroFields.verifySignature(sigName);
                assertTrue("signature verification", p7.verify());
            } finally {
                if (reader != null) {
                    reader.close();
                }
                FileUtils.deleteQuietly(outFile);
            }
        } finally {
            if (largePDF300 != null) {
                FileUtils.deleteQuietly(largePDF300);
            }
        }
    }
    
    /**
     * Test signing of a large JAR.
     * @throws Exception 
     */
    @Test
    public void test40LargeJAR() throws Exception {
        LOG.info("test40LargeJAR");

        Certificate certificate = test.getWorkerSession().getSignerCertificate(new WorkerIdentifier(JARCHIVESIGNER_ID));
        
        File largeJAR300 = null;
        try {
            // Create a x MB JAR document
            largeJAR300 = new File(repository, "largefile-300.jar");
            largeJAR300.deleteOnExit();

            try (
                    ZipFile zipSrc = new ZipFile(new File(PathUtil.getAppHome(), "res/test/HelloJar.jar"));
                    ZipOutputStream zipDest = new ZipOutputStream(new FileOutputStream(largeJAR300))
                ) {
                
                // For each entry in the source file copy them to dest file
                Enumeration<? extends ZipEntry> entries = zipSrc.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    String name = entry.getName();

                    if (entry.isDirectory()) {
                        zipDest.putNextEntry(entry);
                    } else {
                        zipDest.putNextEntry(entry);
                        IOUtils.copyLarge(zipSrc.getInputStream(entry), zipDest);
                        zipDest.closeEntry();
                    }
                }
                
                // Add the large file
                ZipEntry entry = new ZipEntry("large-file.bin");
                zipDest.putNextEntry(entry);
                try (FileInputStream fin = new FileInputStream(large300)) {
                    IOUtils.copyLarge(fin, zipDest);
                }
                zipDest.closeEntry();        
            }
            LOG.info("File size: " + largeJAR300.length());

            File outFile = null;
            JarFile jar = null;
            try {
                outFile = File.createTempFile("large-jar", "-signed.tmp", repository);

                execute("signdocument", 
                                "-workername", JARCHIVESIGNER_NAME, 
                                "-infile", largeJAR300.getAbsolutePath(),
                                "-outfile", outFile.getAbsolutePath());
                
                if (outFile.length() < largeJAR300.length()) {
                    throw new Exception("outFile only " + outFile.length() + " bytes. Out of disk space?");
                }

                // Verify signature (with the included certificate)
                jar = new JarFile(outFile, true);

                // Need each entry so that future calls to entry.getCodeSigners will return anything
                Enumeration<JarEntry> entries = jar.entries();
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    LOG.info("Reading " + entry);
                    IOUtils.copyLarge(jar.getInputStream(entry), new NullOutputStream());
                }

                // Now check each entry
                entries = jar.entries();
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    if (!entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".SF")
                            && !entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".DSA")
                            && !entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".EC")
                            && !entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".RSA")
                            && !entry.getName().endsWith("/")) {

                        // Check that there is a code signer
                        LOG.debug("Veriyfing " + entry);
                        assertNotNull("code signers for entry: " + entry, entry.getCodeSigners());
                        assertEquals("Number of signatures in entry: " + entry, 1, entry.getCodeSigners().length);
                    } else {
                        LOG.info("Ignoring non-class entry: " + entry);
                    }
                }
            } finally {
                if (jar != null) {
                    jar.close();
                }
                FileUtils.deleteQuietly(outFile);
            }
        } finally {
            if (largeJAR300 != null) {
                FileUtils.deleteQuietly(largeJAR300);
            }
        }
    }

    /**
     * Remove the workers created etc.
     * @throws Exception in case of error
     */
    @Test
    public void test99TearDownDatabase() throws Exception {
        test.removeWorker(test.getSignerIdCMSSigner1());
        test.removeWorker(test.getSignerIdPDFSigner1());
        test.removeWorker(PLAINSIGNER_ID);
        test.removeWorker(JARCHIVESIGNER_ID);
    }

    private byte[] execute(String... args) throws IOException, IllegalCommandArgumentsException, CommandFailureException {
        return execute(new SignDocumentCommand(), args);
    }
    
    private byte[] execute(SignDocumentCommand instance, String... args) throws IOException, IllegalCommandArgumentsException, CommandFailureException {
        byte[] result;
        final PrintStream origOut = System.out;
        final PrintStream origErr = System.err;
        
        final ByteArrayOutputStream bStdOut = new ByteArrayOutputStream();
        final PrintStream stdOut = new PrintStream(bStdOut);
        System.setOut(stdOut);
        
        final ByteArrayOutputStream bErrOut = new ByteArrayOutputStream();
        final PrintStream errOut = new PrintStream(bErrOut);
        System.setErr(errOut);
        
        instance.init(new CommandContext("group1", "signdocument", new CommandFactoryContext(new Properties(), stdOut, errOut)));
        try {
            instance.execute(args);
        } finally {
            result = bStdOut.toByteArray();
            System.setOut(origOut);
            System.setErr(origErr);
            System.out.write(result);
            
            byte[] error = bErrOut.toByteArray();
            System.err.write(error);
        }
        return result;
    }
}
