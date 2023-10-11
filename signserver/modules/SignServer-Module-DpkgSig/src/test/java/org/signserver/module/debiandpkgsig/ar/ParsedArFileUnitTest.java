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
package org.signserver.module.debiandpkgsig.ar;

import org.signserver.debiandpkgsig.ar.ParsedArFile;
import org.signserver.debiandpkgsig.ar.ArFileHeader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;
import org.apache.commons.io.output.NullOutputStream;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.util.encoders.Hex;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.util.PathUtil;
import org.signserver.debiandpkgsig.ar.ParsedArFile.Entry;

/**
 * Unit tests for ParsedArFile.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ParsedArFileUnitTest {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(ParsedArFileUnitTest.class);

    private static File sampleFile;
    private static File sampleNonArFile;
    private static File sampleBrokenAr;
    private static File paddedAr;

    private static final String SAMPLE_DEBIAN_BINARY_DIGEST =
            "d526eb4e878a23ef26ae190031b4efd2d58ed66789ac049ea3dbaf74c9df7402";
    private static final String SAMPLE_CONTROL_DIGEST =
            "987e75f558abe9fa948e86b1cbb45865a89ec9c1527331486864e88a4b6b3e05";
    private static final String SAMPLE_DATA_DIGEST =
            "7df86e50feb5570ffbbde922a4da7171256238038b70b5de37003908b30f051f";

    private static final String PADDED_FILE1_DIGEST =
            "d4555ecc0ea2902da7786d097af585bbf2e3104c52d4985b823ba6512d20200b";
    private static final String PADDED_FILE2_DIGEST =
            "b004ecccb7575e513ddb0f6e77670fad05785996bd65d28a388f9ec810f80254";

    @BeforeClass
    public static void setUpClass() throws Exception {
        // Sample package to test with
        sampleFile = new File(PathUtil.getAppHome(), "res/test/HelloDeb.deb");
        if (!sampleFile.exists()) {
            throw new Exception("Missing sample package: " + sampleFile);
        }
        // Sample non-AR file
        sampleNonArFile = new File(PathUtil.getAppHome(), "res/test/HelloDeb.txt");
        if (!sampleNonArFile.exists()) {
            throw new Exception("Missing sample non-AR file: " + sampleNonArFile);
        }
        // Sample non-conforming AR file (has header, but bogus contents)
        sampleBrokenAr = new File(PathUtil.getAppHome(), "res/test/broken.ar");
        if (!sampleBrokenAr.exists()) {
            throw new Exception("Missing broken AR file: " + sampleBrokenAr);
        }
        
        // Sample AR file with an entry of odd size
        paddedAr = new File(PathUtil.getAppHome(), "res/test/padded.ar");
        if (!paddedAr.exists()) {
            throw new Exception("Missing AR file with padded entry: " + paddedAr);
        }
    }

    /**
     * Test parsing an AR file (a Debian package is used here).
     * 
     * @throws Exception 
     */
    @Test
    public void testParse() throws Exception {
        LOG.info("testParse");
        try (final FileInputStream fis = new FileInputStream(sampleFile)) {
            final AlgorithmIdentifier algo =
                    new AlgorithmIdentifier(CMSAlgorithm.SHA256);
            final ParsedArFile paf =
                    ParsedArFile.parseCopyAndHash(fis, new NullOutputStream(), algo);
            final List<ParsedArFile.Entry> entries = paf.getEntries();

            assertEquals("Number of entries", 3, entries.size());
            checkEntry(entries.get(0), "debian-binary", 4,
                       SAMPLE_DEBIAN_BINARY_DIGEST, algo);
            checkEntry(entries.get(1), "control.tar.xz", 336,
                       SAMPLE_CONTROL_DIGEST, algo);
            checkEntry(entries.get(2), "data.tar.xz", 256,
                       SAMPLE_DATA_DIGEST, algo);
        }
    }
    
    /**
     * Test parsing an AR file with padded entries.
     * 
     * @throws Exception 
     */
    @Test
    public void testParsePadded() throws Exception {
        LOG.info("testParsePadded");
        try (final FileInputStream fis = new FileInputStream(paddedAr)) {
            final AlgorithmIdentifier algo =
                    new AlgorithmIdentifier(CMSAlgorithm.SHA256);
            final ParsedArFile paf =
                    ParsedArFile.parseCopyAndHash(fis, new NullOutputStream(), algo);
            final List<ParsedArFile.Entry> entries = paf.getEntries();

            assertEquals("Number of entries", 2, entries.size());
            checkEntry(entries.get(0), "file1/", 5,
                       PADDED_FILE1_DIGEST, algo);
            checkEntry(entries.get(1), "file2/", 7,
                       PADDED_FILE2_DIGEST, algo);
        }
    }

    /**
     * Test that attempting to parse a non-AR file fails in an expected way.
     * 
     * @throws Exception 
     */
    @Test
    public void testParseNonArFileFail() throws Exception {
        LOG.info("testParseNonArFileFail");
        try (final FileInputStream fis = new FileInputStream(sampleNonArFile)) {
            final ParsedArFile paf = ParsedArFile.parse(fis);
            fail("Should throw IOException");
        } catch (IOException e) {
            assertEquals("Contains failure message", "Missing AR magic",
                         e.getMessage());
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
            throw e;
        }
    }

    /**
     * Test that attempting to parse a non-AR file fails in an expected way.
     * 
     * @throws Exception 
     */
    @Test
    public void testParseBrokenArFileFail() throws Exception {
        LOG.info("testParseBrokenArFileFail");
        try (final FileInputStream fis = new FileInputStream(sampleBrokenAr)) {
            final ParsedArFile paf = ParsedArFile.parse(fis);
            fail("Should throw IOException");
        } catch (IOException e) {
            assertEquals("Contains failure message",
                         "Missing file header end characters", e.getMessage());
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
            throw e;
        }
    }
    
    /**
     * Check an AR file entry
     * 
     * @param entry Entry to check
     * @param expectedIdentifier Expected file identifier in the header (file name)
     * @param expectedFileSize Expected file size in the header
     * @param expectedDigest Hex-encoded expected digest
     * @param digestAlgo Digest algorithm used when parsing the AR file
     * @throws Exception 
     */
    private void checkEntry(final Entry entry,
                            final String expectedIdentifier,
                            final int expectedFileSize,
                            final String expectedDigest,
                            final AlgorithmIdentifier digestAlgo) throws Exception {
        final ArFileHeader header = entry.getHeader();

        assertEquals("File identifier", expectedIdentifier,
                     header.getFileIdentifier());
        assertEquals("File size", expectedFileSize, header.getFileSize());

        final byte[] digest = entry.getDigest().get(digestAlgo);
        assertEquals("Matching digests", expectedDigest, Hex.toHexString(digest));
    }
}
