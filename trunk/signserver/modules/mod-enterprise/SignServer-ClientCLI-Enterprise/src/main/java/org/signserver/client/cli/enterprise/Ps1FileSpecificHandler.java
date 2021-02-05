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
import net.jsign.DigestAlgorithm;
import net.jsign.script.PowerShellScript;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.signserver.common.IllegalRequestException;

/**
 * Handler for Power Shell scripts.
 *
 * @author Markus Kilås
 * @version $Id: PEFileSpecificHandler.java 11151 2019-08-18 13:38:22Z netmackan $
 */
public class Ps1FileSpecificHandler extends AbstractFileSpecificHandler {

    private PowerShellScript ps1File;

    public Ps1FileSpecificHandler(File inFile, File outFile) {
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
        ps1File = new PowerShellScript(getOutFile());

        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(algorithm);
        // first check whether digestAlgorithm is valid
        if (digestAlgorithm == null) {
            throw new NoSuchAlgorithmException();
        }
        
        MessageDigest md = MessageDigest.getInstance(algorithm);

        computeDigest = ps1File.computeDigest(md);

        return new InputSource(new ByteArrayInputStream(computeDigest),
                               computeDigest.length);
    }

    @Override
    public void assemble(final OutputCollector oc) throws IOException, IllegalArgumentException {
        try {
            final CMSSignedData signature = new CMSSignedData(oc.toByteArray());
            ps1File.setSignature(signature);
            
            try {
                ps1File.save();
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        } catch (CMSException e) {
            throw new IllegalArgumentException("Signature output is not a CMSSignedData structure", e);
        }
    }

    @Override
    public String getFileTypeIdentifier() {
        return "PS1";
    }

}
