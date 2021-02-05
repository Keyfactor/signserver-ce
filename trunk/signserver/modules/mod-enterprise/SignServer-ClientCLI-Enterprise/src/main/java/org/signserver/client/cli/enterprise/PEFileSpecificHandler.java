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
import java.util.List;
import net.jsign.DigestAlgorithm;
import net.jsign.pe.CertificateTableEntry;
import net.jsign.pe.DataDirectoryType;
import net.jsign.pe.PEFile;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.signserver.common.IllegalRequestException;
import org.signserver.module.msauthcode.common.AuthCodeUtils;

/**
 * Handler for Portable Executable (PE), i.e. Windows executables, DLLs
 * and drivers.
 *
 * @author Marcus Lundblad
 * @author Markus Kilås
 * @version $Id$
 */
public class PEFileSpecificHandler extends AbstractFileSpecificHandler {

    private PEFile peFile;

    public PEFileSpecificHandler(File inFile, File outFile) {
        super(inFile, outFile);
    }

    @Override
    public boolean isSignatureInputHash() {
        return true;
    }

    @Override
    public InputSource produceSignatureInput(String algorithm) throws NoSuchAlgorithmException, IOException, IllegalRequestException {
        FileUtils.copyFile(getInFile(), getOutFile(), false);

        byte[] computeDigest;
        peFile = closeLater(new PEFile(getOutFile()));

        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(algorithm);
        // first check whether digestAlgorithm is valid
        if (digestAlgorithm == null) {
            throw new NoSuchAlgorithmException();
        }
        
        peFile.pad(8);
        computeDigest = peFile.computeDigest(digestAlgorithm);

        return new InputSource(new ByteArrayInputStream(computeDigest),
                               computeDigest.length);
    }

    @Override
    public void assemble(final OutputCollector oc) throws IOException, IllegalArgumentException {
        try {
            CMSSignedData signature = new CMSSignedData(oc.toByteArray());

            final List<CMSSignedData> signatures = peFile.getSignatures();

            if (!signatures.isEmpty()) {
                // append the nested signature
                signature = AuthCodeUtils.addNestedSignature(signatures.get(0), signature);
            }
            
            peFile.writeDataDirectory(DataDirectoryType.CERTIFICATE_TABLE,
                              createCertificateTableEntry(signature).toBytes());
        } catch (CMSException e) {
            throw new IllegalArgumentException("Signature output is not a CMSSignedData structure", e);
        }
    }

    private CertificateTableEntry createCertificateTableEntry(final CMSSignedData signature)
            throws IOException {
        return new CertificateTableEntry(signature);
    }

    @Override
    public String getFileTypeIdentifier() {
        return "PE";
    }

}
