/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.client.cli.enterprise;

import org.signserver.client.cli.defaultimpl.InputSource;
import org.signserver.client.cli.defaultimpl.OutputCollector;
import org.signserver.client.cli.defaultimpl.AbstractFileSpecificHandler;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.CRC32;
import java.util.zip.Checksum;
import org.apache.commons.io.output.CountingOutputStream;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.signserver.common.IllegalRequestException;
import org.signserver.module.jarchive.impl.signapk.ApkHelper;

/**
 * Handles JAR files.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class JarFileSpecificHandler extends AbstractFileSpecificHandler {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(JarFileSpecificHandler.class);

    private final int alignment;
    private final boolean keepSignatures;
    private final boolean replaceSignature;
    private final String signatureName;
    private final long timestamp;
    
    private byte[] sf;
    
    private JarOutputStream jarOut;

    public JarFileSpecificHandler(File inFile, File outFile, int alignment, boolean keepSignatures, boolean replaceSignature, String signatureName, long timestamp) {
        super(inFile, outFile);
        this.alignment = alignment;
        this.keepSignatures = keepSignatures;
        this.replaceSignature = replaceSignature;
        this.signatureName = signatureName;
        this.timestamp = timestamp;
    }

    @Override
    public boolean isSignatureInputHash() {
        return false; // The input is the whole signature file (.SF)
    }

    @Override
    public InputSource produceSignatureInput(String algorithm) throws NoSuchAlgorithmException, IOException {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm must be provided");
        }
        if (algorithm.equalsIgnoreCase("SHA-1")) {
            algorithm = "SHA1";
        }

        JarFile inputJar = null;
        try {
            inputJar = new JarFile(getInFile(), false);  // Don't verify.
            
            try {
                Manifest manifest = ApkHelper.addDigestsToManifest(inputJar, Arrays.asList(algorithm), ApkHelper.CREATED_BY);
                CountingOutputStream cout = new CountingOutputStream(new FileOutputStream(getOutFile()));
                jarOut = closeLater(new JarOutputStream(cout));
                jarOut.setLevel(9);

                long offset = 0;
                // META-INF
                final JarEntry metaInfEntry = new JarEntry("META-INF/");

                final Checksum crc = new CRC32();

                crc.update(new byte[0], 0, 0);
                
                metaInfEntry.setMethod(JarEntry.STORED);
                metaInfEntry.setTime(timestamp);
                metaInfEntry.setSize(0);
                metaInfEntry.setCompressedSize(0);
                metaInfEntry.setCrc(crc.getValue());
                
                // add an additional 4 bytes of "JAR magic" since it's the first entry
                offset += JarFile.LOCHDR + metaInfEntry.getName().length() + 4;

                if (alignment > 0 && (offset % alignment != 0)) {
                    // Set the "extra data" of the entry to between 1 and
                    // alignment-1 bytes, to make the file data begin at
                    // an aligned offset.
                    final int needed = alignment - (int)(offset % alignment);
                    metaInfEntry.setExtra(new byte[needed]);
                    offset += needed;
                }

                jarOut.putNextEntry(metaInfEntry);
                
                // MANIFEST.MF
                JarEntry mfEntry = new JarEntry(JarFile.MANIFEST_NAME);
                mfEntry.setTime(timestamp);
                
                offset += JarFile.LOCHDR + mfEntry.getName().length(); // this is not the first entry
                
                if (alignment > 0 && (offset % alignment != 0)) {
                    // Set the "extra data" of the entry to between 1 and
                    // alignment-1 bytes, to make the file data begin at
                    // an aligned offset.
                    final int needed = alignment - (int)(offset % alignment);
                    mfEntry.setExtra(new byte[needed]);
                    offset += needed;
                }

                // Put the manifest and count its length
                jarOut.putNextEntry(mfEntry);
                cout.resetByteCount();
                manifest.write(jarOut);
                jarOut.closeEntry();
                offset += cout.getByteCount();

                // Copy the rest of the files
                ApkHelper.copyFiles(offset, manifest, inputJar, jarOut, alignment, keepSignatures, replaceSignature, signatureName);
                
                // Write Signature File (SF)
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ApkHelper.writeSignatureFile(manifest, baos, algorithm, ApkHelper.CREATED_BY);
                sf = baos.toByteArray();
                JarEntry je = new JarEntry("META-INF/" + signatureName + ".SF");
                if (timestamp != -1) {
                    je.setTime(timestamp);
                }
                jarOut.putNextEntry(je);
                jarOut.write(sf);
                
                return new InputSource(new ByteArrayInputStream(sf), sf.length);
            } catch (GeneralSecurityException ex) {
                throw new IOException("Unable to digest", ex);
            }
        } catch (IllegalRequestException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Failed: " + ex.getMessage(), ex);
            }
            throw new IOException("Failed: " + ex.getMessage());
        } finally {
            if (inputJar != null) {
                try {
                    inputJar.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }

    @Override
    public void assemble(final OutputCollector oc) throws IOException, IllegalArgumentException {
        final byte[] sigBytes = oc.toByteArray();
        
        try {
            final CMSSignedData signedData = new CMSSignedData(sigBytes);
            JarEntry je = new JarEntry("META-INF/" + signatureName + ".RSA"); // TODO: name and type
            je.setTime(timestamp);
            jarOut.putNextEntry(je);

            ASN1InputStream asn1 = new ASN1InputStream(signedData.getEncoded());
            ASN1OutputStream dos =
                    ASN1OutputStream.create(jarOut, ASN1Encoding.DER);
            dos.writeObject(asn1.readObject());
        } catch (CMSException e) {
            throw new IOException(e);
        }
    }

    @Override
    public String getFileTypeIdentifier() {
        return "ZIP";
    }
}
