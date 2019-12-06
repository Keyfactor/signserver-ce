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
import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.io.FileUtils;
import org.apache.poi.poifs.filesystem.DirectoryEntry;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.signserver.common.IllegalRequestException;
import org.signserver.module.msauthcode.common.MSIUtils;

/**
 * Implementation of FileSpecificHandler for MSI installer packages.
 *
 * @author Marcus Lundblad
 * @author Markus Kilås
 * @version $Id$
 */
public class MSIFileSpecificHandler extends AbstractFileSpecificHandler {

    public MSIFileSpecificHandler(File inFile, File outFile) {
        super(inFile, outFile);
    }

    @Override
    public boolean isSignatureInputHash() {
        return true;
    }

    @Override
    public InputSource produceSignatureInput(String algorithm) throws NoSuchAlgorithmException, IOException, IllegalRequestException {
        FileUtils.copyFile(getInFile(), getOutFile(), false);

        try (final POIFSFileSystem fs = new POIFSFileSystem(getOutFile())) {
            final DirectoryEntry root = fs.getRoot();
            
            // first check whether file is already signed
            if (root.hasEntry("\05DigitalSignature") ||
                root.hasEntry("\05MsiDigitalSignatureEx")) {
                throw new IllegalRequestException("MSI package already signed");
            }
            
            final MessageDigest md = MessageDigest.getInstance(algorithm);
            MSIUtils.traverseDirectory(fs, root, md);
            
            final byte[] digest = md.digest();
            
            return new InputSource(new ByteArrayInputStream(digest), digest.length);
        }
    }

    @Override
    public void assemble(final OutputCollector oc) throws IOException {
        try (final POIFSFileSystem fsOut = new POIFSFileSystem(getOutFile(), false)) { // TODO: move to field and handle in close()
            final CMSSignedData signature = new CMSSignedData(oc.toByteArray());
            // Add the signature file
            fsOut.createDocument(new ByteArrayInputStream(signature.toASN1Structure().getEncoded("DER")),
                                 "\05DigitalSignature");

            // Write out
            fsOut.writeFilesystem(); 
        } catch (CMSException e) {
            throw new IllegalArgumentException("Signature output is not a CMSSignedData structure", e);
        }
    }

    @Override
    public String getFileTypeIdentifier() {
        return "MSI";
    }

}
