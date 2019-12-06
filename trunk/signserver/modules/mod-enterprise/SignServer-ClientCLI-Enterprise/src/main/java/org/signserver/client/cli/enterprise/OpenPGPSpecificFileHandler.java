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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.signserver.client.cli.defaultimpl.AbstractFileSpecificHandler;
import org.signserver.client.cli.defaultimpl.InputSource;
import org.signserver.client.cli.defaultimpl.OutputCollector;
import org.signserver.common.CompileTimeSettings;

/**
 * File specific handler signing anything and producing an OpenPGP detached
 * signature.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class OpenPGPSpecificFileHandler extends AbstractFileSpecificHandler {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(OpenPGPSpecificFileHandler.class);

    public static enum OutputFormat {
        ARMORED,
        BINARY
    };

    private TwoPhasePGPContentSignerBuilder contentSignerBuilder;
    private PGPSignatureSubpacketVector hashedSubpackets;
    private final long keyId;
    private final int keyAlgorithm;
    private final OutputFormat outputFormat;
    private final boolean detached;
    private int hashDigestAlgorithm;
    

    public OpenPGPSpecificFileHandler(final File inFile,
                                      final File outFile,
                                      final long keyId,
                                      final int keyAlgorithm,
                                      final OutputFormat outputFormat,
                                      final boolean detached) {
        super(inFile, outFile);
        this.keyId = keyId;
        this.keyAlgorithm = keyAlgorithm;
        this.outputFormat = outputFormat;
        this.detached = detached;
    }

    @Override
    public boolean isSignatureInputHash() {
        return true;
    }

    @Override
    public InputSource produceSignatureInput(String algorithm) throws NoSuchAlgorithmException, IOException {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm must be provided");
        }

        hashDigestAlgorithm = OpenPGPFileHandlerUtils.getPGPAlgorithm(algorithm);

        try {
            // Setup the builders to be used now and later when generating final signature
            contentSignerBuilder =
                    new TwoPhasePGPContentSignerBuilder(keyAlgorithm,
                                                        hashDigestAlgorithm,
                                                        detached ?
                                                        PGPSignature.BINARY_DOCUMENT :
                                                        PGPSignature.CANONICAL_TEXT_DOCUMENT,
                                                        keyId);
            PGPSignatureSubpacketGenerator subGenerator = new PGPSignatureSubpacketGenerator();
            subGenerator.setSignatureCreationTime(false, new Date());
            hashedSubpackets = subGenerator.generate();

            // Init signature generator (note: same way as in assemble)
            final PGPSignatureGenerator generator = createAndInitializeSignatureGenerator();

            try (final InputStream fIn = new BufferedInputStream(new FileInputStream(getInFile()))) {
                if (detached) {
                    final byte[] buffer = new byte[4096];
                    int n = 0;
                    while (-1 != (n = fIn.read(buffer))) {
                        generator.update(buffer, 0, n);
                    }
                } else {
                    OpenPGPFileHandlerUtils.hashClearText(generator, fIn);
                }
            }

            // Finish the generation and get the digest
            generator.generate();
            final byte[] digest2 = contentSignerBuilder.getDigest();
            final byte[] encoded =
                    OpenPGPFileHandlerUtils.getEncoded(digest2, keyAlgorithm,
                                                       hashDigestAlgorithm);

            // create metadata map
            final Map<String, String> metadata = new HashMap<>();

            metadata.put("KEY_ID", Long.toHexString(keyId));
            metadata.put("KEY_ALGORITHM", Integer.toString(keyAlgorithm));

            // Return the signature input
            return new InputSource(new ByteArrayInputStream(encoded),
                                   encoded.length, null, metadata);
            
        } catch (PGPException | SignatureException ex) {
            ex.printStackTrace();
            throw new IOException("Unable to prepare signature: " + ex.getMessage(), ex);
        }
    }

    @Override
    public void assemble(final OutputCollector oc) throws IOException, IllegalArgumentException {
        final byte[] sigBytes = oc.toByteArray();

        try {
            // Init signature generator (note: same way as in produceSignatureOutput)
            final PGPSignatureGenerator generator = createAndInitializeSignatureGenerator();

            // Set fixed signature
            contentSignerBuilder.setFixedSignature(sigBytes);

            // Generate and write the final output
            final OutputStream os;
            final FileOutputStream fos =
                    new FileOutputStream(getOutFile());
            
            switch (outputFormat) {
                case ARMORED:
                    final ArmoredOutputStream aOut = new ArmoredOutputStream(fos);

                    aOut.setHeader(ArmoredOutputStream.VERSION_HDR,
                                   CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_VERSION));

                    if (!detached) {
                        try (final BufferedInputStream fIn =
                                new BufferedInputStream(new FileInputStream(getInFile()))) {
                            OpenPGPFileHandlerUtils.processClearText(aOut, fIn,
                                                                     hashDigestAlgorithm);
                        } catch (SignatureException e) {
                            throw new IOException("Failed to generate clear-text output", e);
                        }
                    }
                    os = aOut;
                    break;
                case BINARY:
                    os = fos;
                    break;
                default:
                    // this should not happen…
                    throw new IllegalArgumentException("Unsupported output format: " +
                            outputFormat.name());
            }

            
            try (final BCPGOutputStream bOut = new BCPGOutputStream(os)) {
                generator.generate().encode(bOut);
            }

        } catch (PGPException ex) {
            throw new IOException("Unable to assemble signature: " + ex.getMessage(), ex);
        }
    }

    @Override
    public String getFileTypeIdentifier() {
        return "PGP";
    }

    private PGPSignatureGenerator createAndInitializeSignatureGenerator() throws PGPException {
        final PGPSignatureGenerator generator = new PGPSignatureGenerator(contentSignerBuilder);
        generator.setHashedSubpackets(hashedSubpackets);
        final PGPPrivateKey pgpPrivateKey = null;
        generator.init(detached ? PGPSignature.BINARY_DOCUMENT :
                                  PGPSignature.CANONICAL_TEXT_DOCUMENT,
                       pgpPrivateKey);

        return generator;
    }
}
