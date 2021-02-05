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
import java.security.NoSuchAlgorithmException;
import org.signserver.common.IllegalRequestException;
import java.io.RandomAccessFile;
import java.io.ByteArrayOutputStream;
import org.signserver.module.msauthcode.common.AppxHelper;

/**
 * Implementation of FileSpecificHandler for APPX packages.
 * 
 * @author Selwyn Oh
 * @version $Id$
 */
public class AppxFileSpecificHandler extends AbstractFileSpecificHandler {

    private AppxHelper.EocdField eocdValues;
    private long longNewCentralDirOffset;
    private RandomAccessFile rafOutput;
    private byte[] byteArrReconstructedCentralDirRecords;

    public AppxFileSpecificHandler(File inFile, File outFile) {
        super(inFile, outFile);
    }

    @Override
    public boolean isSignatureInputHash() {
        return true;
    }

    @Override
    public InputSource produceSignatureInput(String algorithm) throws NoSuchAlgorithmException, IOException, IllegalRequestException {
        // Input and output files
        rafOutput = closeLater(new RandomAccessFile(getOutFile(), "rw"));
        RandomAccessFile rafInput = closeLater(new RandomAccessFile(getInFile(), "r"));

        // Wrapper for tracking new central directory offset after repackaging Appx file
        AppxHelper.CentralDirectoryOffset offset = new AppxHelper.CentralDirectoryOffset();

        // Reconstructed central directory after repackaging Appx file
        ByteArrayOutputStream baosReconstructedCentralDirRecords = new ByteArrayOutputStream();

        // EOCD field data - used to reconstruct EOCD
        eocdValues = new AppxHelper.EocdField();

        final byte[] digest = AppxHelper.produceSignatureInput(rafInput, rafOutput, algorithm, offset, baosReconstructedCentralDirRecords, eocdValues);

        // Set modified values
        this.longNewCentralDirOffset = offset.getCentralDirOffset();
        this.byteArrReconstructedCentralDirRecords = baosReconstructedCentralDirRecords.toByteArray();

        return new InputSource(new ByteArrayInputStream(digest), digest.length);
    }

    @Override
    public void assemble(final OutputCollector oc) throws IOException {
        AppxHelper.assemble(this.rafOutput, oc.toByteArray(), this.longNewCentralDirOffset, this.byteArrReconstructedCentralDirRecords, this.eocdValues);
    }

    @Override
    public String getFileTypeIdentifier() {
        return "APPX";
    }

}
